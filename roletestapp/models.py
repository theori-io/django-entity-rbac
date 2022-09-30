import enum

from django.db import models
from django.conf import settings
from django_entity_rbac.models import (
    AccessControlledModelMixin,
    create_manager_class,
    Superuser,
    NotSuperuser,
    Anonymous,
)


@enum.unique
class AccessRole(enum.IntFlag):
    '''
    ANONYMOUS, PUBLIC and SUPERUSER are exclusive
    '''

    ANONYMOUS = 1 << 0
    PUBLIC = 1 << 1
    AUTHOR = 1 << 2
    MODERATOR = 1 << 3
    SUPERUSER = 1 << 4

    NONE = 0
    ALL = ~0


class ParentModel(AccessControlledModelMixin, models.Model):
    role_annotations = {
        'current_membership': models.FilteredRelation(
            'memberships', condition=models.Q(
                memberships__user='cur_user'
            )
        )
    }
    role_conditions = {
        AccessRole.MODERATOR: models.Q(current_membership__isnull=False),
        AccessRole.ANONYMOUS: Anonymous,
        AccessRole.PUBLIC: NotSuperuser,
        AccessRole.SUPERUSER: Superuser,
    }
    role_permissions = {
        'test': AccessRole.MODERATOR,
    }

    name = models.CharField(max_length=15, blank=True)
    members = models.ManyToManyField(settings.AUTH_USER_MODEL,
                                     through='Membership',
                                     related_name='pd_roletestapp_parentmodel')

    objects = create_manager_class()

    def __str__(self):
        return '<P[%s]%s>' % (self.pk, self.name)


class Membership(models.Model):
    class Meta:
        constraints = (
            models.UniqueConstraint(fields=('parentmodel', 'user'), name='memb_uniq'),
        )

    parentmodel = models.ForeignKey(ParentModel, on_delete=models.CASCADE, related_name='memberships')
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='pd_roletestapp_memberships')

    def __str__(self):
        return '<Membership %s - %s>' % (self.parentmodel, self.user)


class ChildModel(AccessControlledModelMixin, models.Model):
    role_linked_models = (
        ('ParentModel', 'parent'),
    )
    role_conditions = {
        AccessRole.AUTHOR: models.Q(author='cur_user'),
    }
    role_permissions = {
        'parent.test': AccessRole.MODERATOR,
        'test': [
            (AccessRole.SUPERUSER, models.Q(visibility=0)),
            (AccessRole.SUPERUSER | AccessRole.MODERATOR, models.Q(visibility=1)),
            (AccessRole.SUPERUSER | AccessRole.MODERATOR | AccessRole.AUTHOR, models.Q(visibility=2)),
            (AccessRole.SUPERUSER | AccessRole.MODERATOR | AccessRole.AUTHOR | AccessRole.PUBLIC, models.Q(visibility=3)),
        ]
    }

    parent = models.ForeignKey(ParentModel, on_delete=models.CASCADE)
    author = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    name = models.CharField(max_length=15, blank=True)
    visibility = models.IntegerField()

    objects = create_manager_class()

    def __str__(self):
        return '<C[%s]%s>' % (self.pk, self.name)
