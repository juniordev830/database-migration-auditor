import unittest
from audit import audit
class AuditTests(unittest.TestCase):
    def test_classifies_destructive_ddl(self):
        result=audit('CREATE TABLE users (id int); DROP TABLE users;')
        self.assertEqual([x['severity'] for x in result],['low','high'])
    def test_classifies_mutations_without_where(self):
        result=audit('DELETE FROM orders; UPDATE users SET active=0;')
        self.assertEqual([x['severity'] for x in result],['high','high'])
    def test_safe_update_is_manual_review(self):
        self.assertEqual(audit('UPDATE users SET active=0 WHERE id=3;')[0]['severity'],'medium')
if __name__=='__main__':unittest.main()
