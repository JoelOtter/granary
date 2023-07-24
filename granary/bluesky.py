"""Bluesky source class.

https://bsky.app/
https://atproto.com/lexicons/app-bsky-actor
https://github.com/bluesky-social/atproto/tree/main/lexicons/app/bsky
"""
import json
import logging
from pathlib import Path
import urllib.parse

from granary import as1
from granary.source import FRIENDS, Source, OMIT_LINK
from lexrpc import Client
from oauth_dropins.webutil import util


# list of dict JSON app.bsky.* lexicons. _load_lexicons lazy loads them from the
# lexicons/ dir.
LEXICONS = []

def _maybe_load_lexicons():
  if not LEXICONS:
    for filename in (Path(__file__).parent / 'lexicons').glob('**/*.json'):
      with open(filename) as f:
        LEXICONS.append(json.load(f))

# Maps AT Protocol NSID collections to path elements in bsky.app URLs.
# Used in at_uri_to_web_url.
#
# eg for mapping a URI like:
#   at://did:plc:z72i7hd/app.bsky.feed.generator/mutuals
# to a frontend URL like:
#   https://bsky.app/profile/did:plc:z72i7hdynmk6r22z27h6tvur/feed/mutuals
COLLECTIONS = {
  'app.bsky.feed.post': 'post',
  'app.bsky.feed.generator': 'feed',
}


def url_to_did_web(url):
  """Converts a URL to a did:web.

  Examples:
  * 'https://foo.com' => 'did:web:foo.com'
  * 'https://foo.com:3000' => 'did:web:foo.com%3A3000'
  * 'https://bar.com/baz/baj' => 'did:web:bar.com:baz:baj'

  https://w3c-ccg.github.io/did-method-web/#example-creating-the-did

  TODO: require https?

  Args:
    url: str

  Returns: str
  """
  parsed = urllib.parse.urlparse(url)
  if not parsed.netloc:
    raise ValueError(f'Invalid URL: {url}')

  did = f'did:web:{urllib.parse.quote(parsed.netloc)}'
  if parsed.path:
    did += f'{parsed.path.replace("/", ":")}'

  return did.strip(':')


def did_web_to_url(did):
  """Converts a did:web to a URL.

  Examples:
  * 'did:web:foo.com' => 'https://foo.com'
  * 'did:web:foo.com%3A3000' => 'https://foo.com:3000'
  * 'did:web:bar.com:baz:baj' => 'https://bar.com/baz/baj'

  https://w3c-ccg.github.io/did-method-web/#read-resolve

  Args:
    did: str

  Returns: str
  """
  if not did or not did.startswith('did:web:'):
    raise ValueError(f'Invalid did:web: {did}')

  did = did.removeprefix('did:web:')
  if ':' in did:
    host, path = did.split(':', 1)
  else:
    host = did
    path = ''

  host = urllib.parse.unquote(host)
  path = urllib.parse.unquote(path.replace(':', '/'))
  return f'https://{host}/{path}'


def at_uri_to_web_url(uri, handle=None):
  """Converts an at:// URI to a https://bsky.app URL.

  Args:
    uri: str, at:// URI
    handle: str, optional user handle. If not provided, defaults to the DID in uri.

  Returns:
    str, https://bsky.app URL
  """
  if not uri:
    return None

  if not uri.startswith('at://'):
    raise ValueError(f'Expected at:// URI, got {uri}')

  parsed = urllib.parse.urlparse(uri)
  did = parsed.netloc
  collection, tid = parsed.path.strip('/').split('/')

  type = COLLECTIONS.get(collection)
  if not type:
    return None

  return f'{Bluesky.user_url(handle or did)}/{type}/{tid}'


def from_as1(obj, from_url=None):
  """Converts an AS1 object to a Bluesky object.

  The objectType field is required.

  Args:
    obj: dict, AS1 object or activity
    from_url: str, optional URL the original object was fetched from.
      Currently unused. TODO: remove?

  Returns: dict, app.bsky.* object

  Raises:
    ValueError
      if the objectType or verb fields are missing or unsupported
  """
  activity = obj
  verb = activity.get('verb') or 'post'
  inner_obj = as1.get_object(activity)
  if inner_obj and verb == 'post':
    obj = inner_obj

  type = obj.get('objectType') or 'note'
  actor = as1.get_object(activity, 'actor')

  # TODO: once we're on Python 3.10, switch this to a match statement!
  if type == 'person':
    # banner is featured image, if available
    banner = None
    for img in util.get_list(obj, 'image'):
      url = img.get('url')
      if img.get('objectType') == 'featured' and url:
        banner = url
        break

    url = util.get_url(obj) or obj.get('id') or ''
    try:
      did_web = url_to_did_web(url)
    except ValueError as e:
      logging.info(f"Couldn't generate did:web: {e}")
      did_web = ''

    # handle is username@domain or domain/path, no scheme or query
    username = obj.get('username')
    parsed = urllib.parse.urlparse(url)
    domain = parsed.netloc
    if username:
      handle = username
      if domain:
        handle += f'@{domain}'
    elif url:
      handle = domain
      if parsed.path not in ('', '/'):
        handle += parsed.path
    else:
      handle = ''

    ret = {
      '$type': 'app.bsky.actor.defs#profileView',
      'displayName': obj.get('displayName'),
      'description': obj.get('summary'),
      'avatar': util.get_url(obj, 'image'),
      'banner': banner,
      'did': did_web,
      # this is a DID
      # atproto/packages/pds/src/api/app/bsky/actor/getProfile.ts#38
      # TODO: should be more specific than domain, many users will be on shared
      # domains
      'handle': handle,
    }

  elif verb == 'share':
    ret = from_as1(inner_obj)
    ret['reason'] = {
      '$type': 'app.bsky.feed.defs#reasonRepost',
      'by': from_as1(actor),
      'indexedAt': util.now().isoformat(),
    }

  elif verb == 'follow':
    assert actor
    ret = {
      '$type': 'app.bsky.graph.follow',
      'subject': actor.get('id') or actor.get('url'),
      'createdAt': obj.get('published', ''),
    }

  elif verb == 'post' and type in ('article', 'comment', 'link', 'mention', 'note'):
    # convert text to HTML and truncate
    src = Bluesky('unused')
    content = obj.get('content')
    text = obj.get('summary') or content or obj.get('name') or ''
    text = src.truncate(text, None, OMIT_LINK)

    facets = []
    if text == content:
      # convert index-based to facets
      for tag in util.get_list(obj, 'tags'):
        facet = {
          '$type': 'app.bsky.richtext.facet',
        }

        url = tag.get('url')
        type = tag.get('objectType')
        if type == 'mention':
          facet['features'] = [{
            '$type': 'app.bsky.richtext.facet#mention',
            'did': (url.removeprefix(f'{Bluesky.BASE_URL}/profile/')
                    if url.startswith(f'{Bluesky.BASE_URL}/profile/did:')
                    else ''),
          }]
        elif type in ('article', 'link', 'note') or url:
          facet['features'] = [{
            '$type': 'app.bsky.richtext.facet#link',
            'uri': url,
          }]

        try:
          start = int(tag['startIndex'])
          if start and obj.get('content_is_html'):
            raise NotImplementedError('HTML content is not supported with index tags')
          end = start + int(tag['length'])

          facet['index'] = {
            # convert indices from Unicode chars (code points) to UTF-8 encoded bytes
            # https://github.com/snarfed/atproto/blob/5b0c2d7dd533711c17202cd61c0e101ef3a81971/lexicons/app/bsky/richtext/facet.json#L34
            'byteStart': len(content[:start].encode()),
            'byteEnd': len(content[:end].encode()),
          }
        except (KeyError, ValueError, IndexError, TypeError):
          pass

        facets.append(facet)

    # images
    images_embed = images_record_embed = None
    images = util.get_list(obj, 'image')

    if images:
      images_embed = {
        '$type': 'app.bsky.embed.images#view',
        'images': [{
          '$type': 'app.bsky.embed.images#viewImage',
          'thumb': img.get('url'),
          'fullsize': img.get('url'),
          'alt': img.get('displayName') or '',
        } for img in images[:4]],
      }
      images_record_embed = {
        '$type': 'app.bsky.embed.images',
        'images': [{
          '$type': 'app.bsky.embed.images#image',
          'image': 'TODO',  # this is a $type: blob
          'alt': img.get('displayName') or '',
        } for img in images[:4]],
      }

    # article/note attachments
    record_embed = record_record_embed = external_embed = external_record_embed = None

    for att in util.get_list(obj, 'attachments'):
      if not att.get('objectType') in ('article', 'link', 'note'):
        continue

      id = att.get('id') or ''
      url = att.get('url') or ''
      if (id.startswith('at://') or id.startswith(Bluesky.BASE_URL) or
          url.startswith('at://') or url.startswith(Bluesky.BASE_URL)):
        # quoted Bluesky post
        embed = from_as1(att).get('post')
        embed['value'] = embed.pop('record', None)
        record_embed = {
          '$type': f'app.bsky.embed.record#view',
          'record': {
            **embed,
            '$type': f'app.bsky.embed.record#viewRecord',
            # override these so that trim_nulls below will remove them
            'downvoteCount': None,
            'replyCount': None,
            'repostCount': None,
            'upvoteCount': None,
          },
        }
        record_record_embed = {
          '$type': f'app.bsky.embed.record',
          'record': {
            'cid': 'TODO',
            'uri': id or url,
          }
        }
      else:
        # external link
        external_record_embed = {
          '$type': f'app.bsky.embed.external',
          'external': {
            '$type': f'app.bsky.embed.external#external',
            'uri': url or id,
            'title': att.get('displayName'),
            'description': att.get('summary') or att.get('content') or '',
          }
        }
        external_embed = {
          '$type': f'app.bsky.embed.external#view',
          'external': {
            **external_record_embed['external'],
            '$type': f'app.bsky.embed.external#viewExternal',
            'thumb': util.get_first(att, 'image'),
          },
        }

    if record_embed and (images_embed or external_embed):
      embed = {
        '$type': 'app.bsky.embed.recordWithMedia#view',
        'record': record_embed,
        'media': images_embed or external_embed,
      }
      record_embed = {
        '$type': 'app.bsky.embed.recordWithMedia',
        'record': record_record_embed,
        'media' : images_record_embed or external_record_embed,
      }
    else:
      embed = record_embed or images_embed or external_embed
      record_embed = record_record_embed or images_record_embed or external_record_embed

    # in reply to
    reply = None
    in_reply_to = as1.get_object(obj, 'inReplyTo')
    if in_reply_to:
      reply = {
        '$type': 'app.bsky.feed.post#replyRef',
        'root': {
          '$type': 'com.atproto.repo.strongRef',
          'uri': '',  # TODO?
          'cid': 'TODO',
        },
        'parent': {
          '$type': 'com.atproto.repo.strongRef',
          'uri': in_reply_to.get('id') or in_reply_to.get('url'),
          'cid': 'TODO',
        },
      }

    # author
    author = as1.get_object(obj, 'author')
    if author:
      author = {
        **from_as1(author),
        '$type': 'app.bsky.actor.defs#profileViewBasic',
      }

    ret = {
      '$type': 'app.bsky.feed.defs#feedViewPost',
      'post': {
        '$type': 'app.bsky.feed.defs#postView',
        'uri': obj.get('id') or obj.get('url') or '',
        'cid': 'TODO',
        'record': {
          '$type': 'app.bsky.feed.post',
          'text': text,
          'createdAt': obj.get('published', ''),
          'embed': record_embed,
          'facets': facets,
          'reply': reply
        },
        'author': author,
        'embed': embed,
        'replyCount': 0,
        'repostCount': 0,
        'upvoteCount': 0,
        'downvoteCount': 0,
        'indexedAt': util.now().isoformat(),
      },
    }

  else:
    raise ValueError(f'AS1 object has unknown objectType {type} or verb {verb}')

  # keep some fields that are required by lexicons
  return util.trim_nulls(ret, ignore=(
    'alt',
    'createdAt',
    'description',
    'did',
    'handle',
    'root',
    'text',
    'uri',
    'viewer',
  ))


def as1_to_profile(actor):
  """Converts an AS1 actor to a Bluesky `app.bsky.actor.profile`.

  Args:
    actor: dict, AS1 actor

  Raises:
    ValueError: if `actor['objectType']` is not in :attr:`as1.ACTOR_TYPES`
  """
  type = actor.get('objectType')
  if type not in as1.ACTOR_TYPES:
    raise ValueError(f'Expected actor type, got {type}')

  profile = from_as1(actor)
  assert profile['$type'] == 'app.bsky.actor.defs#profileView'
  profile['$type'] = 'app.bsky.actor.profile'

  for field in 'did', 'handle', 'indexedAt', 'labels', 'viewer':
    profile.pop(field, None)

  return profile


def to_as1(obj, type=None):
  """Converts a Bluesky object to an AS1 object.

  The $type field is required.

  Args:
    profile: dict, app.bsky.* object
    type: str, optional $type to parse with, only used if obj['$type'] is unset

  Returns: dict, AS1 object

  Raises:
    ValueError if the $type field is missing or unsupported
  """
  if not obj:
    return {}

  type = obj.get('$type') or type
  if not type:
    raise ValueError('Bluesky object missing $type field')

  # TODO: once we're on Python 3.10, switch this to a match statement!
  if type in (
          'app.bsky.actor.defs#profileView',
          'app.bsky.actor.defs#profileViewBasic',
          'app.bsky.actor.defs#profileViewDetailed'):

    handle = obj.get('handle')
    did = obj.get('did')

    ret = {
      'objectType': 'person',
      'id': did,
      'url': (Bluesky.user_url(handle) if handle
              else did_web_to_url(did) if did and did.startswith('did:web:')
              else None),
      'displayName': obj.get('displayName'),
      'summary': obj.get('description'),
      'image': {'url': obj.get('avatar')},
    }

  elif type == 'app.bsky.feed.post':
    text = obj.get('text', '')

    # convert facets to tags
    tags = []
    for facet in obj.get('facets', []):
      tag = {}

      for feat in facet.get('features', []):
        if feat.get('$type') == 'app.bsky.richtext.facet#link':
          tag.update({
            'objectType': 'article',
            'url': feat.get('uri'),
          })
        elif feat.get('$type') == 'app.bsky.richtext.facet#mention':
          tag.update({
            'objectType': 'mention',
            'url': Bluesky.user_url(feat.get('did')),
          })

      index = facet.get('index', {})
      # convert indices from UTF-8 encoded bytes to Unicode chars (code points)
      # https://github.com/snarfed/atproto/blob/5b0c2d7dd533711c17202cd61c0e101ef3a81971/lexicons/app/bsky/richtext/facet.json#L34
      byte_start = index.get('byteStart')
      if byte_start is not None:
        tag['startIndex'] = len(text.encode()[:byte_start].decode())
      byte_end = index.get('byteEnd')
      if byte_end is not None:
        tag['displayName'] = text.encode()[byte_start:byte_end].decode()
        tag['length'] = len(tag['displayName'])

      tags.append(tag)

    in_reply_to = obj.get('reply', {}).get('parent', {}).get('uri')

    ret = {
      'objectType': 'comment' if in_reply_to else 'note',
      'content': text,
      'inReplyTo': [{
        'id': in_reply_to,
        'url': at_uri_to_web_url(in_reply_to),
      }],
      'published': obj.get('createdAt', ''),
      'tags': tags,
    }

  elif type in ('app.bsky.feed.defs#postView', 'app.bsky.embed.record#viewRecord'):
    ret = to_as1(obj.get('record') or obj.get('value'))
    author = obj.get('author') or {}
    uri = obj.get('uri')
    ret.update({
      'id': uri,
      'url': (at_uri_to_web_url(uri, handle=author.get('handle'))
              if uri.startswith('at://') else None),
      'author': to_as1(author, type='app.bsky.actor.defs#profileViewBasic'),
    })

    # convert embeds to attachments
    for embed in util.get_list(obj, 'embeds') + util.get_list(obj, 'embed'):
      embed_type = embed.get('$type')

      if embed_type == 'app.bsky.embed.images#view':
        ret.setdefault('image', []).extend(to_as1(embed))

      elif embed_type in ('app.bsky.embed.external#view',
                          'app.bsky.embed.record#view'):
        ret.setdefault('attachments', []).append(to_as1(embed))

      elif embed_type == 'app.bsky.embed.recordWithMedia#view':
        ret.setdefault('attachments', []).append(to_as1(
          embed.get('record', {}).get('record')))
        media = embed.get('media')
        media_type = media.get('$type')
        if media_type == 'app.bsky.embed.external#view':
          ret.setdefault('attachments', []).append(to_as1(media))
        elif media_type == 'app.bsky.embed.images#view':
          ret.setdefault('image', []).extend(to_as1(media))
        else:
          assert False, f'Unknown embed media type: {media_type}'

  elif type == 'app.bsky.embed.images#view':
    ret = [{
      'url': img.get('fullsize'),
      'displayName': img.get('alt'),
    } for img in obj.get('images', [])]

  elif type == 'app.bsky.embed.external#view':
    ret = to_as1(obj.get('external'), type='app.bsky.embed.external#viewExternal')

  elif type == 'app.bsky.embed.external#viewExternal':
    ret = {
      'objectType': 'link',
      'url': obj.get('uri'),
      'displayName': obj.get('title'),
      'summary': obj.get('description'),
      'image': obj.get('thumb'),
    }

  elif type == 'app.bsky.embed.record#view':
    record = obj.get('record')
    return to_as1(record) if record else None

  elif type == 'app.bsky.embed.record#viewNotFound':
    return None

  elif type in ('app.bsky.embed.record#viewNotFound',
                'app.bsky.embed.record#viewBlocked'):
    return None

  elif type == 'app.bsky.feed.defs#feedViewPost':
    ret = to_as1(obj.get('post'), type='app.bsky.feed.defs#postView')
    reason = obj.get('reason')
    if reason and reason.get('$type') == 'app.bsky.feed.defs#reasonRepost':
      ret = {
        'id': obj.get('post').get('viewer').get('repost'),
        'objectType': 'activity',
        'verb': 'share',
        'object': ret,
        'actor': to_as1(reason.get('by'), type='app.bsky.actor.defs#profileViewBasic'),
      }

  elif type == 'app.bsky.graph.follow':
    ret = {
      'objectType': 'activity',
      'verb': 'follow',
      'actor': {
        'url': obj.get('subject'),
      },
    }

  elif type == 'app.bsky.feed.defs#threadViewPost':
    return to_as1(obj.get('post'), type='app.bsky.feed.defs#postView')

  elif type == 'app.bsky.feed.defs#generatorView':
    uri = obj.get('uri')
    ret = {
      'objectType': 'service',
      'id': uri,
      'url': at_uri_to_web_url(uri),
      'displayName': f'Feed: {obj.get("displayName")}',
      'summary': obj.get('description'),
      'image': obj.get('avatar'),
      'author': to_as1(obj.get('creator'), type='app.bsky.actor.defs#profileView'),
    }

  else:
    raise ValueError(f'Bluesky object has unknown $type: {type}')

  return util.trim_nulls(ret)


class Bluesky(Source):
  """Bluesky source class. See file docstring and Source class for details.

  Attributes:
    handle: str
    did: str
    access_token: str
  """

  DOMAIN = 'bsky.app'
  BASE_URL = 'https://bsky.app'
  NAME = 'Bluesky'
  TRUNCATE_TEXT_LENGTH = 300  # TODO: load from feed.post lexicon
  URL_CANONICALIZER = util.UrlCanonicalizer(
          domain=DOMAIN,
          # Bluesky does not support HEAD requests.
          redirects=False)

  def __init__(self, handle, did=None, access_token=None, app_password=None):
    """Constructor.

    Either access_token or app_password may be provided, optionally, but not both.

    Args:
      handle: str username, eg 'snarfed.bsky.social' or 'snarfed.org'
      did: str, did:plc or did:web, optional
      access_token: str, optional
      app_password: str, optional
    """
    assert not (access_token and app_password)

    _maybe_load_lexicons()

    if app_password:
      client = Client('https://bsky.social', LEXICONS)
      resp = client.com.atproto.server.createSession({
        'identifier': handle,
        'password': app_password,
      })
      self.handle = resp['handle']
      self.did = resp['did']
      self.access_token = resp['accessJwt']
      assert self.access_token
    else:
      self.handle = handle
      self.access_token = access_token
      self.did = did

    headers = None
    if self.access_token:
      headers = {
        'Authorization': f'Bearer {self.access_token}',
      }
    self.client = Client('https://bsky.social', LEXICONS, headers=headers)

  @classmethod
  def user_url(cls, handle):
    """Returns the profile URL for a given handle.

    Args:
      handle: str

    Returns:
      str, profile URL
    """
    return f'{cls.BASE_URL}/profile/{handle.lstrip("@")}'

  @classmethod
  def post_url(cls, handle, tid):
    """Returns the post URL for a given handle and tid.

    Args:
      handle: str
      tid: str

    Returns:
      str, profile URL
    """
    return f'{cls.user_url(handle)}/post/{tid}'

  def get_activities_response(self, user_id=None, group_id=None, app_id=None,
                              activity_id=None, fetch_replies=True,
                              fetch_likes=True, fetch_shares=True,
                              include_shares=False, fetch_events=False,
                              fetch_mentions=False, search_query=None,
                              start_index=None, count=None, cache=None, **kwargs):
    """Fetches posts and converts them to AS1 activities.

    See :meth:`Source.get_activities_response` for more information.

    Bluesky-specific details:

    Args:
      * activity_id: str, an at:// URI
    """
    assert not start_index

    params = {}
    if count is not None:
      params['limit'] = count

    posts = None

    if activity_id:
      if not activity_id.startswith('at://'):
        raise ValueError(f'Expected activity_id to be at:// URI; got {activity_id}')
      resp = self.client.app.bsky.feed.getPostThread({}, uri=activity_id, depth=1)
      posts = [resp.get('thread', {})]

    elif group_id in (None, FRIENDS):
      resp = self.client.app.bsky.feed.getTimeline({}, **params)
      posts = resp.get('feed', [])

    else:  # eg group_id SELF
      handle = user_id or self.handle or self.did
      if not handle:
        raise ValueError('user_id is required')
      resp = self.client.app.bsky.feed.getAuthorFeed({}, actor=handle, **params)
      posts = resp.get('feed', [])

    if cache is None:
      # for convenience, throwaway object just for this method
      cache = {}

    activities = []

    for post in posts:
      if not include_shares:
        reason = post.get('reason')
        if reason and reason.get('$type') == 'app.bsky.feed.defs#reasonRepost':
          continue

      activity = self.postprocess_activity(self._post_to_activity(post))
      activities.append(activity)
      obj = activity['object']
      id = obj['id']
      tags = obj.setdefault('tags', [])

      bs_post = post.get('post')
      if bs_post:
        # Likes
        like_count = bs_post.get('likeCount')
        if fetch_likes and like_count and like_count != cache.get('ABL ' + id):
          likers = self.client.app.bsky.feed.getLikes({}, uri=bs_post.get('uri'))
          tags.extend(self._make_like(bs_post, l.get('actor')) for l in likers.get('likes'))
          cache['ABL ' + id] = count

        # Reposts
        repost_count = bs_post.get('repostCount')
        if fetch_shares and repost_count and repost_count != cache.get('ABRP ' + id):
          reposters = self.client.app.bsky.feed.getRepostedBy({}, uri=bs_post.get('uri'))
          tags.extend(self._make_share(bs_post, r) for r in reposters.get('repostedBy'))
          cache['ABRP ' + id] = count

        # Replies
        reply_count = bs_post.get('replyCount')
        if fetch_replies and reply_count and reply_count != cache.get('ABR ' + id):
          replies = self._get_replies(bs_post.get('uri'))
          replies = [to_as1(reply, 'app.bsky.feed.defs#threadViewPost') for reply in replies]
          for r in replies:
            r['id'] = self.tag_uri(r['id'])
          obj['replies'] = {
            'items': replies,
          }
          cache['ABR ' + id] = count

    resp = self.make_activities_base_response(util.trim_nulls(activities))
    return resp

  def user_to_actor(self, user):
    """Converts a dict user to an actor.

    Args:
      user: Bluesky user app.bsky.actor.defs#profileViewDetailed

    Returns:
      an ActivityStreams actor dict, ready to be JSON-encoded
    """
    return to_as1(user)

  def get_comment(self, comment_id, **kwargs):
    """Fetches and returns a comment.

    Args:
      comment_id: string status id
      **kwargs: unused

    Returns: dict, ActivityStreams object

    Raises:
      :class:`ValueError`: if comment_id is invalid
    """
    post_thread = self.client.app.bsky.feed.getPostThread({}, uri=comment_id)
    obj = to_as1(post_thread.get('thread'), 'app.bsky.feed.defs#threadViewPost')
    return obj

  def _post_to_activity(self, post):
    """Converts a post to an activity.

    Args:
      post: Bluesky post app.bluesky.feed.defs#feedViewPost

    Returns: AS1 activity
    """
    obj = to_as1(post, type='app.bsky.feed.defs#feedViewPost')
    return {
      'verb': 'post',
      'published': obj.get('published'),
      'id': obj.get('id'),
      'url': obj.get('url'),
      'actor': obj.get('author'),
      'object': obj,
      'context': {'inReplyTo': obj.get('inReplyTo')},
    }

  def _make_like(self, post, actor):
    return self._make_like_or_share(post, actor, 'like')

  def _make_share(self, post, actor):
    return self._make_like_or_share(post, actor, 'share')

  def _make_like_or_share(self, post, actor, verb):
    """Generates and returns a ActivityStreams like object.

    Args:
      post: dict, Bluesky app.bsky.feed.defs#feedViewPost
      actor: dict, Bluesky app.bsky.actor.defs#profileView
      verb: string, 'like' or 'share'

    Returns: dict, AS1 like activity
    """
    assert verb in ('like', 'share')
    label = 'favorited' if verb == 'like' else 'reblogged'
    url = at_uri_to_web_url(post.get('uri'), post.get('author').get('handle'))
    actor_id = actor.get('did')
    author = to_as1(actor, 'app.bsky.actor.defs#profileView')
    author['id'] = self.tag_uri(author['id'])
    return {
      'id': self.tag_uri(f"{post.get('uri')}_{label}_by_{actor_id}"),
      'url': url,
      'objectType': 'activity',
      'verb': verb,
      'object': {'url': url},
      'author': author,
    }

  def _get_replies(self, uri):
    """
    Gets the replies to a specific post and returns them
    in ascending order of creation. Does not include the original post.

    Args:
      uri: string, post uri

    Returns: array, Bluesky app.bsky.feed.defs#threadViewPost
    """
    ret = []
    resp = self.client.app.bsky.feed.getPostThread({}, uri=uri)
    thread = resp.get('thread')
    if thread:
      ret = self._recurse_replies(thread)
    return sorted(ret, key = lambda thread: thread.get('post').get('record').get('createdAt'))

  def _recurse_replies(self, thread):
    """
    Recurses through a Bluesky app.bsky.feed.defs#threadViewPost
    and returns its replies as an array.

    Args:
      thread: dict, Bluesky app.bsky.feed.defs#threadViewPost

    Returns: array, Bluesky app.bsky.feed.defs#threadViewPost
    """
    ret = []
    for r in thread.get('replies'):
        ret += [r]
        ret += self._recurse_replies(r)
    return ret
