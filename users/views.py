from django.shortcuts import render
from django.contrib import messages
from django.template.context_processors import request
from rest_framework import status,permissions
from rest_framework.response import Response
from .models import CustomUser
from rest_framework.views import APIView
from django.contrib.auth import authenticate
from rest_framework.exceptions import ValidationError
from rest_framework_simplejwt.tokens import RefreshToken,TokenError
from .serializers import SignUpSerializer,UserUpdateSerializer,UserProfileSerializer,ChangePassword
from rest_framework.permissions import IsAuthenticated
from rest_framework.generics import UpdateAPIView,GenericAPIView


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



class UserUpdateView(UpdateAPIView):
    permission_classes = (IsAuthenticated,)
    queryset = CustomUser.objects.all()
    serializer_class = UserUpdateSerializer

    def get_object(self):
        return self.request.user



    def update(self,request,*args,**kwargs):
        user=self.get_object()
        return Response({
            "status":status.HTTP_200_OK,
            "message":"Malumotlar o'zgartirildi",
            "user":user.username
        })



    def partial_update(self, request, *args, **kwargs):
        return Response({
            "status": status.HTTP_200_OK,
            "message": "Malumotlar qisman o'zgartirildi"
        })


class UserProfileView(GenericAPIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = UserProfileSerializer
    queryset = CustomUser

    def get(self,request):
        user=request.user
        serializer=UserProfileSerializer(user)

        data={
            "status":status.HTTP_200_OK,
            "user":serializer.data,
        }

        return Response(data)



class ChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]

    def put(self, request):
        serializer = ChangePassword(instance=request.user,data=request.data,context={"request": request})
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({"message": "Parol muvaffaqiyatli o‘zgartirildi"}, status=status.HTTP_200_OK)




class LoginRefreshView(APIView):
    permission_classes = ()
    def post(self, request):
        refresh_token = request.data.get('refresh_token')

        if not refresh_token:
            raise ValidationError({"message": "refresh_token yuborilmadi"})

        try:
            refresh = RefreshToken(refresh_token)
            access_token = str(refresh.access_token)

            return Response({
                "status": status.HTTP_200_OK,
                "access": access_token
            })

        except Exception:
            raise ValidationError({"message": "Refresh token noto‘g‘ri yoki muddati tugagan"})





















