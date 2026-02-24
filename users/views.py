from django.shortcuts import render
from django.contrib import messages
from rest_framework import status,permissions
from rest_framework.response import Response
from .models import CustomUser
from rest_framework.views import APIView
from django.contrib.auth import authenticate
from rest_framework.exceptions import ValidationError
from rest_framework_simplejwt.tokens import RefreshToken,TokenError
from .serializers import SignUpSerializer
from rest_framework.permissions import IsAuthenticated



class SignUpView(APIView):
    def post(self,request):
        serializer=SignUpSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user=serializer.save()
        response={
            'status':status.HTTP_201_CREATED,
            'message':user.username
        }
        return Response(response)


class LoginView(APIView):
    def post(self,request):
        username=self.request.data.get('username')
        password=self.request.data.get('password')

        user=authenticate(username=username,password=password)

        if not user:
            raise ValidationError({'message':'Username yoki parol notogri'})

        refresh_token=RefreshToken.for_user(user=user)

        response={
            'status':status.HTTP_201_CREATED,
            'message':'Siz royxatdan otdingiz',
            'refresh':str(refresh_token),
            'access':str(refresh_token.access_token)
            }
        return Response(response)


class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        refresh_token = request.data.get("refresh")
        if not refresh_token:
            response={
                "status":status.HTTP_400_BAD_REQUEST,
                "error":"Refresh token kerak"
            }
            return Response(response)

        try:
            token = RefreshToken(refresh_token)
            token.blacklist()
            response={
                "status":status.HTTP_205_RESET_CONTENT,
                "message":"Chiqish muvaffaqiyatli"
            }
            return Response(response)
        except TokenError:
            response={
                "status":status.HTTP_400_BAD_REQUEST,
                "error":"Token notogri muddati otgan"
            }
            return Response(response)