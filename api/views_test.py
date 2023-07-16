from rest_framework.test import APIClient
from rest_framework.test import APITestCase
from rest_framework import status
from core_app.models import Message
from core_app.services.encryption_service import EncryptionService
from urllib.parse import quote


class MessageViewTestCase(APITestCase):

    """
    Test suite for Message
    """
    def setUp(self):
        self.client = APIClient()

        self.url = "/api/messages/"
        self.data = {
            "body": "This is a dummy message",
            "destroyLiveAfterSeconds": "30",
            "password": "dummy_password",
            "destroyAfterDays": "7"
        }
        self.encryption_service = EncryptionService()

    def test_create_message(self):
        data = self.data
        response = self.client.post(self.url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(Message.objects.count(), 1)
        #Should exist, but be encrypted
        self.assertNotEqual(Message.objects.get().body, "This is a dummy message")

    def test_create_contact_without_password(self):
        data = self.data
        data.pop("password")
        response = self.client.post(self.url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_create_contact_without_password(self):
        data = self.data
        data["password"] = ""
        response = self.client.post(self.url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
    
    def test_create_message_when_body_equals_blank(self):
        data = self.data
        data["body"] = ""
        response = self.client.post(self.url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_create_message_without_body(self):
        data = self.data
        data.pop("body")
        response = self.client.post(self.url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_create_message_without_destroyAfterDays(self):
        data = self.data
        data.pop("destroyAfterDays")
        response = self.client.post(self.url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
    
    def test_create_contact_when_destroyAfterDays_equals_blank(self):
        data = self.data
        data["destroyAfterDays"] = ""
        response = self.client.post(self.url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_create_message_without_destroyLiveAfterSeconds(self):
        data = self.data
        data.pop("destroyLiveAfterSeconds")
        response = self.client.post(self.url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
    
    def test_create_message_when_destroyLiveAfterSeconds_equals_blank(self):
        data = self.data
        data["destroyLiveAfterSeconds"] = ""
        response = self.client.post(self.url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_get_message_whith_false_password(self):
        '''
        Should not remove the message from the database
        '''
        # GIVEN
        message = Message(
            body="This is a dummy message",
            destroyLiveAfterSeconds=30,
            password="dummy_password",
            destroyAfterDays=30
        )
        message.save()

        # When
        data = self.data
        data["destroyLiveAfterSeconds"] = ""
        response = self.client.get(self.url + str(message.id) + "?pw=wrongpassword", data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIsNotNone(Message.objects.get(id=message.id))


    def test_get_message_whithout_password(self):
        '''
        Should not remove the message from the database
        '''
        # GIVEN
        message = Message(
            body="This is a dummy message",
            destroyLiveAfterSeconds=30,
            password="dummy_password",
            destroyAfterDays=30
        )
        message.save()

        # When
        data = self.data
        data["destroyLiveAfterSeconds"] = ""
        response = self.client.get(self.url + str(message.id), data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIsNotNone(Message.objects.get(id=message.id))


    def test_post_message_get_message(self):
        '''
        Should return the same message
        '''
        # Given
        body = "This is a dummy message"
        destroyLiveAfterSeconds = 30
        password = "dummy_password"
        message = {
            "body": str(body),
            "destroyLiveAfterSeconds": str(destroyLiveAfterSeconds),
            "password": str(password),
            "destroyAfterDays": "7"
        }
        post_response = self.client.post(self.url, message)
        self.assertEqual(post_response.status_code, status.HTTP_200_OK)
        self.assertIsNotNone(Message.objects.get(id=post_response.data['data']))
        # When
        encoded_password = self.encryption_service.encode_str_to_base64(password)
        url_safe_encoded_password = quote(encoded_password)
        url = self.url + str(post_response.data['data']) + "?pw=" + url_safe_encoded_password
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['body'], body)
        self.assertEqual(response.data['destroyLiveAfterSeconds'], destroyLiveAfterSeconds)