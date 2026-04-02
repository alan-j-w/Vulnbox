from django.test import TestCase, Client
from django.urls import reverse
from authapp.models import CustomUser

class LabTests(TestCase):
    def setUp(self):
        self.user = CustomUser.objects.create_user(
            username='hacker1',
            email='h@example.com',
            password='password123'
        )
        self.client.login(email='h@example.com', password='password123')

    def test_sql_injection_lab(self):
        # Test valid payload for flag reveal
        response = self.client.post(reverse('core:sql_injection'), {'query': "' UNION SELECT 1,2,3--"})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'FLAG{sql_injection_success_e4b1}')

    def test_flag_submission_logic(self):
        # Valid flag submission
        response = self.client.post(reverse('core:submit_flag'), {'flag': 'FLAG{sql_injection_success_e4b1}'})
        self.user.refresh_from_db()
        self.assertEqual(self.user.score, 15)
        self.assertIn('SQL Injection', self.user.completed_challenges)

    def test_double_flag_submission(self):
        # Submit the same flag twice
        self.client.post(reverse('core:submit_flag'), {'flag': 'FLAG{sql_injection_success_e4b1}'})
        response = self.client.post(reverse('core:submit_flag'), {'flag': 'FLAG{sql_injection_success_e4b1}'})
        self.user.refresh_from_db()
        self.assertEqual(self.user.score, 15) # Points should NOT have doubled
