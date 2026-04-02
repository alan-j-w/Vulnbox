from django.test import TestCase
from django.urls import reverse
from authapp.models import CustomUser

class UserProfileTests(TestCase):
    def setUp(self):
        self.user = CustomUser.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpassword123'
        )

    def test_user_creation(self):
        self.assertEqual(self.user.username, 'testuser')
        self.assertEqual(self.user.email, 'test@example.com')
        self.assertTrue(self.user.is_active)

    def test_is_online(self):
        # By default, last_seen is now, so user should be "online"
        self.assertTrue(self.user.is_online())

    def test_profile_view_protected(self):
        response = self.client.get(reverse('core:profile'))
        self.assertEqual(response.status_code, 302) # Redirect to login
