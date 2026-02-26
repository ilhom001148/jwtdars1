from rest_framework import serializers,status
from rest_framework.permissions import AllowAny
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken

from .models import CustomUser
from rest_framework.exceptions import ValidationError



class SignUpSerializer(serializers.ModelSerializer):
    password=serializers.CharField(write_only=True,required=True)
    conf_password=serializers.CharField(write_only=True,required=True)

    class Meta:
        model=CustomUser
        fields=['username','first_name','last_name','email','phone_number','address','password','conf_password']

    def validate(self,data):
        password=data.get('password',None)
        conf_password=data.get('conf_password',None)

        if password is None or conf_password is None or password != conf_password:
            response={
                'status':status.HTTP_400_BAD_REQUEST,
                'message':'Parollar mos emas yoki xato kiritildi'
            }
            raise ValidationError(response)
        if len([i for i in password if i==' '])>0:
            response={
                'status':status.HTTP_400_BAD_REQUEST,
                'message':'Parollar xato kiritildi'
            }
            raise ValidationError(response)
        return data


    def validate_username(self,username):
        if len(username)<7:
            raise ValidationError({'message':'Username kamida 7 ta bolishi kerak'})
        elif not username.isalnum():
            raise ValidationError({'message':'Usernameda ortiqcha belgilar bolmasligi kerak'})
        elif username[0].isdigit():
            raise ValidationError({'message':'Username raqam bilan boshlanmasin'})
        return username

    def create(self,validated_data):
        validated_data.pop('conf_password')

        user=CustomUser.objects.create_user(**validated_data)
        return user


class UserUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model=CustomUser
        fields=['username','first_name','last_name','email','phone_number']

        def update(self,instance,validated_data):
            instance.username=validated_data.get('username',instance.username)
            instance.first_name=validated_data.get('first_name',instance.first_name)
            instance.last_name=validated_data.get('last_name',instance.last_name)
            instance.email=validated_data.get('email',instance.email)
            instance.phone_number=validated_data.get('phone_number',instance.phone_number)

            instance.save()
            return Response(instance)



class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model=CustomUser
        fields=['username','first_name','last_name','email','phone_number']



class ChangePassword(serializers.Serializer):
    old_password=serializers.CharField(required=True,write_only=True)
    new_password=serializers.CharField(required=True,write_only=True)
    confirm_password=serializers.CharField(required=True,write_only=True)

    def validate(self, attrs):
        old_password=attrs.get('old_password')
        new_password=attrs.get('new_password')
        confirm_password=attrs.get('confirm_password')

        if old_password == new_password:
            raise ValidationError({"message":"yangi parol eskisi bilan bir xil bulmasligi kerak"})
        if new_password != confirm_password:
            raise ValidationError({"message":"yangi parollar mos emas"})
        if " " in new_password:
            raise ValidationError({"message": "parolda probel bo‘lishi mumkin emas"})

        return attrs

    def update(self, instance, validated_data):
        is_valid = instance.check_password(validated_data.get('old_password'))
        if not is_valid:
            raise ValidationError({"message": "eski parol noto‘g‘ri"})

        instance.set_password(validated_data.get('new_password'))
        instance.save()
        return instance
















