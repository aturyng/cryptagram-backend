from django.shortcuts import render

# Create your views here.
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .serializers import MessageSerializer
from core_app.models import Message
from core_app.services.encryption_service import EncryptionService
from injector import inject
from urllib.parse import quote_plus, unquote_to_bytes

class MessageViews(APIView):

    @inject
    def __init__(self, encryption_service: EncryptionService):
        self.encryption_service = encryption_service
        super().__init__()

    def post(self, request, *args, **kwargs):
        serializer = MessageSerializer(data=request.data)
        if serializer.is_valid():
            # Hash password before saving
            password = serializer.validated_data['password']
            if password != "":
                hashed_password = self.encryption_service.hash_password(password)

                salt = self.encryption_service.generate_salt()
                aes_key = self.encryption_service.derive_aes_key_from_password(password, salt)

                iv = self.encryption_service.generate_iv()
                ciphertext = self.encryption_service.encrypt_string(aes_key, iv, serializer.validated_data['body'])
                encrypted_body_with_additions = self.encryption_service.join_salt_iv_ciphertext(salt, iv, ciphertext)
                # Update values
                serializer.validated_data['password'] = hashed_password
                serializer.validated_data['body'] = encrypted_body_with_additions
            # Save
            serializer.save()
            return Response({"status": "success", "data": serializer.data['id']}, status=status.HTTP_200_OK)
        else:
            return Response({"status": "error", "data": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

    def __get_object(self, message_id):
        '''
        Helper method to get the object with given message_id
        '''
        try:
            return Message.objects.get(id=message_id)
        except Message.DoesNotExist:
            return None

    def get(self, request, message_id, *args, **kwargs):
        '''
        Retrieves the message with given id
        '''
        message_instance = self.__get_object(message_id)
        if not message_instance:
            
            return Response(
                {"res": "Object with message id does not exists"},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            encoded_password_base64 = request.query_params.get('pw')
           
            decoded_password_base64 = encoded_password_base64.replace(' ', '+')
            password_str = self.encryption_service.decode_base64_str(decoded_password_base64)
            plaint_text = self.encryption_service.decrypt(message_instance.body, password_str)
            message_instance.body = plaint_text
            serializer = MessageSerializer(message_instance)
            message_instance.delete()
            return Response(serializer.data, status=status.HTTP_200_OK)
        except:
            return Response(
                {"res": "An error occured while processing request"},
                status=status.HTTP_400_BAD_REQUEST
            )