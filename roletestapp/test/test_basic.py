import itertools
from uuid import UUID
from django.test import TestCase
from django.db.models import Q
from django_entity_rbac.constants import CONTEXT_USER_FIELD, ACCESS_ROLE_FIELD
from django.contrib.auth.models import User

from ..models import AccessRole, ParentModel, Membership, ChildModel


class TestBasicRoleFetch(TestCase):

    def setUp(self):
        defaults = {'is_active': True}

        def global_roles(user):
            if not (user and user.is_authenticated):
                return AccessRole.ANONYMOUS
            if user.is_superuser:
                return AccessRole.SUPERUSER
            return AccessRole.PUBLIC

        self.user_admin = User.objects.create(
            username='admin', is_superuser=True,
            **defaults
        )
        self.user_alice = User.objects.create(
            username='alice', **defaults
        )
        self.user_bob = User.objects.create(
            username='bob', **defaults
        )
        self.user_carol = User.objects.create(
            username='carol', **defaults
        )
        self.user_ted = User.objects.create(
            username='ted', **defaults
        )
        self.users = [
            self.user_admin,
            self.user_alice,
            self.user_bob,
            self.user_carol,
            self.user_ted
        ]
        user_roles = {user.pk: global_roles(user) for user in self.users}

        self.parent_alpha = ParentModel.objects.create(name='alpha')
        self.parent_beta = ParentModel.objects.create(name='beta')
        self.parent_insts = [
            self.parent_alpha,
            self.parent_beta
        ]
        self.parent_roles = {
            parent.pk: user_roles.copy()
            for parent in self.parent_insts
        }

        self.membership_alpha_carol = Membership.objects.create(
            parentmodel=self.parent_alpha,
            user=self.user_carol
        )
        self.parent_roles[self.parent_alpha.pk][self.user_carol.pk] |= AccessRole.MODERATOR

        self.membership_beta_ted = Membership.objects.create(
            parentmodel=self.parent_beta,
            user=self.user_ted
        )
        self.parent_roles[self.parent_beta.pk][self.user_ted.pk] |= AccessRole.MODERATOR

        self.child_roles = {}

        self.child_foo = ChildModel.objects.create(
            parent=self.parent_alpha,
            name='foo',
            visibility=0
        )
        self.child_roles[self.child_foo.pk] = self.parent_roles[self.parent_alpha.pk].copy()

        self.child_bar = ChildModel.objects.create(
            parent=self.parent_alpha,
            author=self.user_carol,
            name='bar',
            visibility=1
        )
        self.child_roles[self.child_bar.pk] = self.parent_roles[self.parent_alpha.pk].copy()
        self.child_roles[self.child_bar.pk][self.user_carol.pk] |= AccessRole.AUTHOR

        self.child_baz = ChildModel.objects.create(
            parent=self.parent_beta,
            author=self.user_alice,
            name='baz',
            visibility=2
        )
        self.child_roles[self.child_baz.pk] = self.parent_roles[self.parent_beta.pk].copy()
        self.child_roles[self.child_baz.pk][self.user_alice.pk] |= AccessRole.AUTHOR

        self.child_qux = ChildModel.objects.create(
            parent=self.parent_beta,
            author=self.user_alice,
            name='qux',
            visibility=3
        )
        self.child_roles[self.child_qux.pk] = self.parent_roles[self.parent_beta.pk].copy()
        self.child_roles[self.child_qux.pk][self.user_alice.pk] |= AccessRole.AUTHOR

        self.child_insts = [
            self.child_foo,
            self.child_bar,
            self.child_baz,
            self.child_qux,
        ]

        self.instances = self.parent_insts + self.child_insts

    def checkrole(self, model, pk, user, roles):
        if isinstance(user, User):
            self.assertEqual(roles, model.objects.annotate_current_access(user).get(pk=pk).get_access_roles(user.id))
            self.assertEqual(roles, model.objects.annotate_current_access(user.id).get(pk=pk).get_access_roles(user))
            self.assertEqual(roles, model.objects.annotate_current_access(user.id).get(pk=pk).get_access_roles(user.id))

        self.assertFalse(model.objects.annotate_current_access(user, filter_q=Q(pk__in=[])).exists())
        self.assertTrue(model.objects.annotate_current_access(user, filter_q=Q()).exists())

    def assert_role_not_cached(self, value):
        self.assertNotIn(CONTEXT_USER_FIELD, value.__dict__.keys())
        self.assertNotIn(ACCESS_ROLE_FIELD, value.__dict__.keys())

    def assert_context_user_only(self, value, user):
        if isinstance(user, User):
            user = user.pk
        if user is None:
            self.assertNotIn(CONTEXT_USER_FIELD, value.__dict__.keys())
        else:
            self.assertEqual(getattr(value, CONTEXT_USER_FIELD), user)
        self.assertNotIn(ACCESS_ROLE_FIELD, value.__dict__.keys())

    def assert_role_cached(self, value, user):
        if isinstance(user, User):
            user = user.pk
        if user is None:
            self.assertNotIn(CONTEXT_USER_FIELD, value.__dict__.keys())
        else:
            self.assertEqual(getattr(value, CONTEXT_USER_FIELD), user)
        self.assertIn(ACCESS_ROLE_FIELD, value.__dict__.keys())

    def getrole(self, model, pk, user):
        raw_inst = model.objects.get(pk=pk)
        self.assert_role_not_cached(raw_inst)

        fresh_roles = raw_inst.get_access_roles(user)
        if user is not None:
            self.assert_role_cached(raw_inst, user)
        else:
            self.assert_role_not_cached(raw_inst)

        if isinstance(user, User):
            self.assertEqual(fresh_roles, model.objects.get(pk=pk).get_access_roles(user.id))

        annot_inst = model.objects.annotate_current_access(user).get(pk=pk)
        self.assert_role_cached(annot_inst, user)
        cached_roles = annot_inst.get_access_roles(user)

        self.assertEqual(fresh_roles, cached_roles)
        self.checkrole(model, pk, user, cached_roles)

        no_annot_inst = model.objects.annotate_current_access(
            user, use_roles_field=False
        ).get(pk=pk)
        self.assert_role_not_cached(no_annot_inst)

        return cached_roles

    def test_null_user(self):
        for inst in self.instances:
            roles = self.getrole(inst.__class__, inst.pk, None)
            self.assertEqual(roles, AccessRole.ANONYMOUS)

    def test_public(self):
        mask = AccessRole.SUPERUSER | AccessRole.PUBLIC | AccessRole.ANONYMOUS
        for user in self.users:
            if user.is_superuser:
                continue
            for inst in self.instances:
                roles = self.getrole(inst.__class__, inst.pk, user)
                self.assertEqual(roles & mask, AccessRole.PUBLIC)

    def test_superuser(self):
        mask = AccessRole.SUPERUSER | AccessRole.PUBLIC | AccessRole.ANONYMOUS
        for inst in self.instances:
            roles = self.getrole(inst.__class__, inst.pk, self.user_admin)
            self.assertEqual(roles & mask, AccessRole.SUPERUSER)

    def test_parent_roles(self):
        for parent_pk, role_map in self.parent_roles.items():
            for user_pk, roles in role_map.items():
                with self.subTest('Access ParentModel %s from User %s' % (parent_pk, user_pk)):
                    roles_from_db = self.getrole(ParentModel, parent_pk, user_pk)
                    self.assertEqual(roles_from_db, roles)

    def test_child_roles(self):
        for child_pk, role_map in self.child_roles.items():
            for user_pk, roles in role_map.items():
                with self.subTest('Access ChildModel %s from User %s' % (child_pk, user_pk)):
                    roles_from_db = self.getrole(ChildModel, child_pk, user_pk)
                    self.assertEqual(roles_from_db, roles)

    def test_filter_roles(self):
        rolelist = [AccessRole.SUPERUSER]
        rolelist.append(rolelist[-1] | AccessRole.MODERATOR)
        rolelist.append(rolelist[-1] | AccessRole.AUTHOR)
        rolelist.append(rolelist[-1] | AccessRole.PUBLIC)

        def dotest(model, user, expect_objs):
            self.assertEqual(set(model.objects.filter_by_access(user, 'test')), expect_objs)
            self.assertEqual(set(model.objects.annotate_current_access(user, filter_roles='test')), expect_objs)
            self.assertEqual(set(model.objects.annotate_current_access(user, filter_roles='test', filter_q=Q())), expect_objs)
            self.assertEqual(set(model.objects.annotate_current_access(user, use_roles_field=False, filter_roles='test')), expect_objs)
            self.assertEqual(set(model.objects.annotate_current_access(user, use_roles_field=False, filter_roles='test', filter_q=Q())), expect_objs)
            self.assertFalse(model.objects.annotate_current_access(user, filter_roles='test', filter_q=Q(pk__in=[])).exists())
            self.assertFalse(model.objects.annotate_current_access(user, use_roles_field=False, filter_roles='test', filter_q=Q(pk__in=[])).exists())

        for user in self.users:
            with self.subTest('Parent access from User %s' % (user.pk,)):
                parent_expect_objs = {
                    parent for parent in self.parent_insts
                    if (self.parent_roles[parent.pk][user.pk]
                        & AccessRole.MODERATOR) != 0
                }
                dotest(ParentModel, user, parent_expect_objs)
            with self.subTest('Child access from User %s' % (user.pk,)):
                child_expect_objs = {
                    child for child in self.child_insts
                    if (self.child_roles[child.pk][user.pk]
                        & rolelist[child.visibility]) != 0
                }
            dotest(ChildModel, user, child_expect_objs)

        with self.subTest('Parent anonymous access'):
            dotest(ParentModel, None, set())

        with self.subTest('Child anonymous access'):
            child_expect_objs = {
                child for child in self.child_insts
                if (AccessRole.ANONYMOUS & rolelist[child.visibility]) != 0
            }
            dotest(ChildModel, None, child_expect_objs)
