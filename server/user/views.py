from django.contrib.auth import authenticate
from django.conf import settings
from django.middleware import csrf
from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema
from rest_framework import (
    exceptions as rest_exceptions,
    response,
    decorators as rest_decorators,
    permissions as rest_permissions,
)
from rest_framework_simplejwt import (
    tokens,
    views as jwt_views,
    serializers as jwt_serializers,
    exceptions as jwt_exceptions,
)
from user import serializers, models
import stripe

stripe.api_key = settings.STRIPE_SECRET_KEY
prices = {
    settings.WORLD_INDIVIDUAL: "world_individual",
    settings.WORLD_GROUP: "world_group",
    settings.WORLD_BUSINESS: "world_business",
    settings.UNIVERSE_INDIVIDUAL: "universe_individual",
    settings.UNIVERSE_GROUP: "universe_group",
    settings.UNIVERSE_BUSINESS: "universe_business",
}


def get_user_tokens(user):
    refresh = tokens.RefreshToken.for_user(user)
    return {"refresh_token": str(refresh), "access_token": str(refresh.access_token)}


@swagger_auto_schema(
    method="post",
    request_body=serializers.LoginSerializer,
    responses={
        200: openapi.Response(
            description="Login successful",
            examples={
                "application/json": {
                    "access_token": "string",
                    "refresh_token": "string",
                }
            },
        ),
        400: "Bad Request",
        401: "Unauthorized",
    },
)
@rest_decorators.api_view(["POST"])
@rest_decorators.permission_classes([])
def loginView(request):
    """
    Log in the user by validating the provided email and password.

    This endpoint logs in the user by validating the provided email and password.
    If the credentials are valid, it returns access and refresh tokens and sets
    the appropriate cookies.

    Returns:
        - 200: Login successful.
        - 401: Email or Password is incorrect.
    """
    serializer = serializers.LoginSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)

    email = serializer.validated_data["email"]
    password = serializer.validated_data["password"]

    user = authenticate(email=email, password=password)

    if user is not None:
        tokens = get_user_tokens(user)
        res = response.Response()
        res.set_cookie(
            key=settings.SIMPLE_JWT["AUTH_COOKIE"],
            value=tokens["access_token"],
            expires=settings.SIMPLE_JWT["ACCESS_TOKEN_LIFETIME"],
            secure=settings.SIMPLE_JWT["AUTH_COOKIE_SECURE"],
            httponly=settings.SIMPLE_JWT["AUTH_COOKIE_HTTP_ONLY"],
            samesite=settings.SIMPLE_JWT["AUTH_COOKIE_SAMESITE"],
        )

        res.set_cookie(
            key=settings.SIMPLE_JWT["AUTH_COOKIE_REFRESH"],
            value=tokens["refresh_token"],
            expires=settings.SIMPLE_JWT["REFRESH_TOKEN_LIFETIME"],
            secure=settings.SIMPLE_JWT["AUTH_COOKIE_SECURE"],
            httponly=settings.SIMPLE_JWT["AUTH_COOKIE_HTTP_ONLY"],
            samesite=settings.SIMPLE_JWT["AUTH_COOKIE_SAMESITE"],
        )

        res.data = tokens
        res["X-CSRFToken"] = csrf.get_token(request)
        return res
    raise rest_exceptions.AuthenticationFailed("Email or Password is incorrect!")


@swagger_auto_schema(
    method="post",
    request_body=serializers.RegistrationSerializer,
    responses={
        200: openapi.Response(description="Registered successfully"),
        400: "Bad Request",
        401: "Invalid credentials",
    },
)
@rest_decorators.api_view(["POST"])
@rest_decorators.permission_classes([])
def registerView(request):
    """
    Register a new user.

    This endpoint registers a new user by validating the provided registration data.
    If the data is valid, it saves the new user and returns a success message.

    Returns:
        - 200: Registered successfully.
        - 400: Invalid credentials.
    """
    serializer = serializers.RegistrationSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)

    user = serializer.save()

    if user is not None:
        return response.Response("Registered!")
    return rest_exceptions.AuthenticationFailed("Invalid credentials!")


@swagger_auto_schema(
    method="post",
    responses={
        200: openapi.Response(description="Logout successful"),
        400: "Bad Request",
        403: "Forbidden",
        404: "Not Found",
    },
)
@rest_decorators.api_view(["POST"])
@rest_decorators.permission_classes([rest_permissions.IsAuthenticated])
def logoutView(request):
    """
    Log out the user by blacklisting the refresh token and clearing cookies.

    This endpoint logs out the user by blacklisting the refresh token and clearing the authentication and CSRF cookies.

    * Requires authentication.

    Returns:
        - 200: Logout successful.
        - 400: Invalid token.
    """
    try:
        refreshToken = request.COOKIES.get(settings.SIMPLE_JWT["AUTH_COOKIE_REFRESH"])
        token = tokens.RefreshToken(refreshToken)
        token.blacklist()

        res = response.Response()
        res.delete_cookie(settings.SIMPLE_JWT["AUTH_COOKIE"])
        res.delete_cookie(settings.SIMPLE_JWT["AUTH_COOKIE_REFRESH"])
        res.delete_cookie("X-CSRFToken")
        res.delete_cookie("csrftoken")
        res["X-CSRFToken"] = None

        return res
    except:
        raise rest_exceptions.ParseError("Invalid token")


class CookieTokenRefreshSerializer(jwt_serializers.TokenRefreshSerializer):
    refresh = None

    def validate(self, attrs):
        attrs["refresh"] = self.context["request"].COOKIES.get("refresh")
        if attrs["refresh"]:
            return super().validate(attrs)
        else:
            raise jwt_exceptions.InvalidToken(
                "No valid token found in cookie 'refresh'"
            )


class CookieTokenRefreshView(jwt_views.TokenRefreshView):
    """
    Refresh the JWT token and set the refresh token in a cookie.
    This endpoint refreshes the JWT token and sets the new refresh token in a cookie.
    """

    serializer_class = CookieTokenRefreshSerializer

    @swagger_auto_schema(
        operation_description="Refresh the JWT token.",
        request_body=CookieTokenRefreshSerializer,
        responses={
            200: openapi.Response(
                description="Token refreshed successfully",
                examples={"application/json": {"access": "string"}},
            ),
            400: "Bad Request",
            401: "Unauthorized",
        },
    )
    def post(self, request, *args, **kwargs):
        return super().post(request, *args, **kwargs)

    def finalize_response(self, request, response, *args, **kwargs):
        if response.data.get("refresh"):
            response.set_cookie(
                key=settings.SIMPLE_JWT["AUTH_COOKIE_REFRESH"],
                value=response.data["refresh"],
                expires=settings.SIMPLE_JWT["REFRESH_TOKEN_LIFETIME"],
                secure=settings.SIMPLE_JWT["AUTH_COOKIE_SECURE"],
                httponly=settings.SIMPLE_JWT["AUTH_COOKIE_HTTP_ONLY"],
                samesite=settings.SIMPLE_JWT["AUTH_COOKIE_SAMESITE"],
            )

            del response.data["refresh"]
        response["X-CSRFToken"] = request.COOKIES.get("csrftoken")
        return super().finalize_response(request, response, *args, **kwargs)


@swagger_auto_schema(
    method="get",
    responses={
        200: openapi.Response(
            description="User details retrieved successfully",
            examples={
                "application/json": {
                    "id": 1,
                    "email": "user@example.com",
                    "first_name": "John",
                    "last_name": "Doe",
                }
            },
            schema=serializers.UserSerializer,
        ),
        404: "User not found",
        401: "Unauthorized",
    },
)
@rest_decorators.api_view(["GET"])
@rest_decorators.permission_classes([rest_permissions.IsAuthenticated])
def user(request):
    """
    Retrieve the authenticated user's details.

    This endpoint retrieves the details of the authenticated user.

    Returns:
        - 200: User details retrieved successfully.
        - 404: User not found.
    """
    try:
        user = models.User.objects.get(id=request.user.id)
    except models.User.DoesNotExist:
        return response.Response(status_code=404)

    serializer = serializers.UserSerializer(user)
    return response.Response(serializer.data)


@swagger_auto_schema(
    method="get",
    responses={
        200: openapi.Response(
            description="Active subscriptions retrieved successfully",
            examples={
                "application/json": {
                    "subscriptions": [
                        {
                            "id": "sub_1",
                            "start_date": "2023-01-01T00:00:00Z",
                            "plan": "Basic Plan",
                        },
                        {
                            "id": "sub_2",
                            "start_date": "2023-02-01T00:00:00Z",
                            "plan": "Premium Plan",
                        },
                    ]
                }
            },
            schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    "subscriptions": openapi.Schema(
                        type=openapi.TYPE_ARRAY,
                        items=openapi.Schema(
                            type=openapi.TYPE_OBJECT,
                            properties={
                                "id": openapi.Schema(
                                    type=openapi.TYPE_STRING,
                                    description="Subscription ID",
                                ),
                                "start_date": openapi.Schema(
                                    type=openapi.TYPE_STRING,
                                    description="Start date of the subscription",
                                ),
                                "plan": openapi.Schema(
                                    type=openapi.TYPE_STRING, description="Plan name"
                                ),
                            },
                        ),
                    )
                },
            ),
        ),
        404: "User not found",
        401: "Unauthorized",
    },
)
@rest_decorators.api_view(["GET"])
@rest_decorators.permission_classes([rest_permissions.IsAuthenticated])
def getSubscriptions(request):
    """
    Retrieve the active subscriptions for the authenticated user.

    This endpoint retrieves the active subscriptions for the authenticated user based on their email.

    Returns:
        - 200: Active subscriptions retrieved successfully.
        - 404: User not found.
    """
    try:
        user = models.User.objects.get(id=request.user.id)
    except models.User.DoesNotExist:
        return response.Response(status_code=404)

    subscriptions = []
    customer = stripe.Customer.search(query=f'email:"{user.email}"')
    if "data" in customer:
        if len(customer["data"]) > 0:
            for _customer in customer["data"]:
                subscription = stripe.Subscription.list(customer=_customer["id"])
                if "data" in subscription:
                    if len(subscription["data"]) > 0:
                        for _subscription in subscription["data"]:
                            if _subscription["status"] == "active":
                                subscriptions.append(
                                    {
                                        "id": _subscription["id"],
                                        "start_date": str(_subscription["start_date"]),
                                        "plan": prices[_subscription["plan"]["id"]],
                                    }
                                )

    return response.Response({"subscriptions": subscriptions}, 200)
