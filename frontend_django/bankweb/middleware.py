import secrets

class RequestIdMiddleware:

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        rid = request.META.get("HTTP_X_REQUEST_ID") or secrets.token_hex(8)
        request.request_id = rid
        try:
            request.session["request_id"] = rid
        except Exception:
            pass

        response = self.get_response(request)

        try:
            response["X-Request-ID"] = rid
        except Exception:
            pass

        return response
