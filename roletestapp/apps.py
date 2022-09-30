from django.apps import AppConfig


class RoleTestAppConfig(AppConfig):
    name = __name__.rsplit('.', 1)[0]
    label = 'roletestapp'
    default_auto_field = 'django.db.models.AutoField'
