from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema
from rest_framework import (
    response,
    decorators as rest_decorators,
    permissions as rest_permissions,
)


@swagger_auto_schema(
    method="post",
    responses={
        200: openapi.Response(
            description="Payment for subscription successful",
            examples={"application/json": {"msg": "Success"}},
        ),
        401: "Unauthorized",
    },
)
@rest_decorators.api_view(["POST"])
@rest_decorators.permission_classes([rest_permissions.IsAuthenticated])
def paySubscription(request):
    """
    Process payment for the subscription.

    This endpoint processes the payment for the subscription of the authenticated user.

    Returns:
        - 200: Payment for subscription successful.
        - 401: Unauthorized if user is not authenticated.
    """
    return response.Response({"msg": "Success"}, 200)


@swagger_auto_schema(
    method="post",
    responses={
        200: openapi.Response(
            description="List of subscriptions retrieved successfully",
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
        401: "Unauthorized",
    },
)
@rest_decorators.api_view(["POST"])
@rest_decorators.permission_classes([rest_permissions.IsAuthenticated])
def listSubscriptions(request):
    """
    List subscriptions of the authenticated user.

    This endpoint retrieves the list of subscriptions for the authenticated user.

    Returns:
        - 200: List of subscriptions retrieved successfully.
        - 401: Unauthorized if user is not authenticated.
    """
    return response.Response({"msg": "Success"}, 200)
