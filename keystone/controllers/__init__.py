def get_url(req):
    return '%s://%s:%s%s' % (
        req.environ['wsgi.url_scheme'],
        req.environ.get("SERVER_NAME"),
        req.environ.get("SERVER_PORT"),
        req.environ['PATH_INFO'])


def get_marker_limit_and_url(req):
    marker = req.GET["marker"] if "marker" in req.GET else None
    limit = req.GET["limit"] if "limit" in req.GET else 10
    url = get_url(req)

    return (marker, limit, url)
