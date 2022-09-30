
import operator
import copy
import string
from collections import OrderedDict

from itertools import product
from functools import reduce

from django.db import models
from django.contrib.auth import get_user_model
from django.apps import apps as django_apps
from django.utils import timezone
from django.core.exceptions import EmptyResultSet
from django.db.models.sql import Query

from .constants import CONTEXT_USER_FIELD, ACCESS_ROLE_FIELD, CURRENT_TIME_FIELD
from .exceptions import InconsistentDatabaseValuesError

try:
    from django.db.models.constants import LOOKUP_SEP
except ImportError:
    LOOKUP_SEP = '__'


class Superuser:
    pass

class NotSuperuser:
    pass

class Anonymous:
    pass

SPECIAL_ROLE_KEYS = frozenset((Superuser, NotSuperuser, Anonymous))

class ConditionGroup:
    def expand(self, roles):
        raise NotImplementedError

    def get_basis_conditions(self):
        raise NotImplementedError


class SimpleConditionGroup(ConditionGroup):
    __slots__ = ('lookup_table', 'basis', 'mask')

    def __init__(self, lookup_table, basis):
        self.lookup_table = lookup_table
        self.basis = basis
        self.mask = reduce(operator.or_, basis, 0)

    def expand(self, roles):
        return self.lookup_table[roles]

    def get_basis_conditions(self):
        lookup_table = self.lookup_table
        return ((key, lookup_table[key]) for key in self.basis)

    def _get_tuple(self):
        return (self.lookup_table, self.basis, self.mask)

    def __eq__(self, other):
        return self is other or (
            isinstance(other, SimpleConditionGroup) and
            self._get_tuple() == other._get_tuple()
        )

    def __ne__(self, other):
        return self is not other and (
            not isinstance(other, SimpleConditionGroup) or
            self._get_tuple() != other._get_tuple()
        )

    def __hash__(self):
        return hash(self._get_tuple())

    def __repr__(self):
        return '{}(lookup_table={!r}, basis={!r})'.format(
            self.__class__.__name__,
            self.lookup_table,
            self.basis
        )

    def __or__(self, other):
        if self == other:
            return self
        return NotImplemented


class BackModelReference:
    __slots__ = ('prefix_id',)

    def __init__(self, prefix_id):
        self.prefix_id = prefix_id

    def __eq__(self, other):
        return (
            isinstance(other, BackReference) and
            self.prefix_id == other.prefix_id
        )

    def __ne__(self, other):
        return (
            not isinstance(other, BackReference) or
            self.prefix_id != other.prefix_id
        )

    def __hash__(self):
        return hash(self.prefix_id)

    def __repr__(self):
        return '{}(prefix_id={!r})'.format(
            self.__class__.__name__,
            self.prefix_id,
        )


class BackReference:
    __slots__ = ('prefix_id', 'name', 'only_roles')

    def __init__(self, prefix_id, name, only_roles=None):
        self.prefix_id = prefix_id
        self.name = name
        self.only_roles = only_roles

    def __eq__(self, other):
        return (
            isinstance(other, BackReference) and
            self.prefix_id == other.prefix_id and
            self.name == other.name and
            self.only_roles == other.only_roles
        )

    def __ne__(self, other):
        return (
            not isinstance(other, BackReference) or
            self.prefix_id != other.prefix_id or
            self.name != other.name or
            self.only_roles != other.only_roles
        )

    def __hash__(self):
        return hash((self.prefix_id, self.name, self.only_roles))

    def __repr__(self):
        return '{}(prefix_id={!r}, name={!r}, only_roles={!r})'.format(
            self.__class__.__name__,
            self.prefix_id,
            self.name,
            self.only_roles
        )


class UnresolvedFilterRoles:
    conditional = True

    def __init__(self, ref):
        self.ref = ref

    def resolve_expression(self, *args, **kwargs):
        raise ValueError('unresolved filter roles: ' + repr(self.ref))

    def __eq__(self, other):
        return isinstance(other, UnresolvedFilterRoles) and self.ref == other.ref

    def __ne__(self, other):
        return not isinstance(other, UnresolvedFilterRoles) or self.ref != other.ref

    def __hash__(self):
        return hash(self.ref)

    def __repr__(self):
        return '{}(refs={!r})'.format(self.__class__.__name__, self.ref)


class FalseExpression(models.Expression):
    output_field = models.BooleanField()
    conditional = True
    contains_aggregate = False

    def resolve_expression(self, *args, **kwargs):
        return self

    def as_sql(self, compiler, connection):
        raise EmptyResultSet

def wrap_condition(condition):
    if condition is None or condition is False:
        return FalseExpression()
    return models.ExpressionWrapper(
        condition,
        output_field=models.BooleanField()
    )

def generate_alphabet_sequence(charset=string.ascii_uppercase, separator=''):
    joiner = str(separator).join
    length = 1
    while True:
        yield from map(joiner, product(charset, repeat=length))
        length += 1


def flatten_condition_map(condition_map):
    for key, cond in condition_map.items():
        if isinstance(cond, ConditionGroup):
            yield from cond.get_basis_conditions()
        else:
            yield key, cond

def combine_or(a, b):
    '''
    Compute a | b, with special casing for Python booleans.
    This is a workaround for Django not having proper ~Q().
    '''
    return (
        True if a is True or b is True else
        b if a is False else a if b is False else
        a | b
    )

def combine_and(a, b):
    '''
    Compute a & b, with special casing for Python booleans.
    This is a workaround for Django not having proper ~Q().
    '''
    return (
        False if a is False or b is False else
        b if a is True else a if b is True else
        a & b
    )

def collect_unconditional_roles(conditional_role_masks, global_role_mask=~0):
    result = []
    unconditional_roles = 0
    for filt_roles, filt_cond in conditional_role_masks:
        if filt_cond is True and not isinstance(filt_roles, BackReference):
            if filt_roles is None:
                unconditional_roles = None
            else:
                assert not isinstance(filt_roles, (list, tuple)), 'unflattened rule found'
                if unconditional_roles is not None:
                    unconditional_roles |= int(filt_roles) & global_role_mask
        else:
            result.append((filt_roles, filt_cond))
    return unconditional_roles, result

def flatten_nested_filter_roles(value):
    while isinstance(value, (list, tuple)):
        if len(value) == 1:
            ((filt_roles, filt_cond),) = value
            if filt_cond is True:
                value = filt_roles
                continue
        elif not value:
            value = 0
        break
    return value

def preoptimize_nested_conditional_role_masks(conditional_role_masks, global_role_mask=~0):
    unconditional_roles, conditional_role_masks = collect_unconditional_roles(
        conditional_role_masks,
        global_role_mask,
    )
    if unconditional_roles is None:
        return [(None, True)] # optimization success (trivial case)

    global_role_mask &= ~unconditional_roles

    result = []
    if unconditional_roles:
        result.append((unconditional_roles, True))

    for filt_roles, filt_cond in conditional_role_masks:
        if isinstance(filt_roles, (list, tuple)):
            filt_roles = preoptimize_nested_conditional_role_masks(filt_roles, global_role_mask)
            filt_roles = flatten_nested_filter_roles(filt_roles)
        if filt_roles is None or isinstance(filt_roles, (list, tuple, BackReference)):
            result.append((filt_roles, filt_cond))
        else:
            filt_roles = int(filt_roles) & global_role_mask
            if filt_roles:
                result.append((filt_roles, filt_cond))

    return result

def compute_access_role_filter_q(flag_exprs, conditional_role_masks,
                                 global_role_mask=~0):
    # mask: (mask_cond & bigwedge[spec_cond...])
    mask_map = {}
    id_to_obj = {}

    result = False

    # First, collect all unconditionally accepted roles
    unconditional_roles, conditional_role_masks = collect_unconditional_roles(
        conditional_role_masks,
        global_role_mask,
    )

    optimized_role_masks = {}
    if unconditional_roles is None:
        result = True
    elif unconditional_roles:
        optimized_role_masks[unconditional_roles] = True

    global_role_mask &= ~unconditional_roles

    # Second, filter out unconditional roles from the rest and merge
    for filt_roles, filt_cond in conditional_role_masks:
        if isinstance(filt_cond, BackReference):
            return UnresolvedFilterRoles(filt_roles)
        if isinstance(filt_roles, (list, tuple)):
            # nested filter spec
            sub_result = compute_access_role_filter_q(
                    flag_exprs, filt_roles,
                    global_role_mask=global_role_mask)
            result = combine_or(result, combine_and(filt_cond, sub_result))
        elif filt_roles is None:  # bypass role check
            result = combine_or(result, filt_cond)
        else:
            filt_roles = int(filt_roles) & global_role_mask
            if filt_roles:
                optimized_role_masks[filt_roles] = combine_or(
                    optimized_role_masks.get(filt_roles, False),
                    filt_cond
                )

    # Third, split conditional roles with respect to the condition
    # FIXME O(nm) computation time -- memoize?
    for filt_roles, filt_cond in optimized_role_masks.items():
        # Resort to identity comparsion, since models.Q.__eq__ is
        # too slow and spec_cond duplicates are unlikely.
        key = id(filt_cond)
        id_to_obj[key] = filt_cond
        for spec_roles, spec_cond in flag_exprs.items():
            mask = filt_roles & int(spec_roles)
            if mask:
                if isinstance(spec_cond, ConditionGroup):
                    spec_cond = spec_cond.expand(mask)
                mask_map[key] = combine_or(mask_map.get(key, False), spec_cond)

    # Fourth, combine into one predicate
    result = reduce(
        combine_or,
        (combine_and(id_to_obj[filt_cond_id], spec_cond)
         for filt_cond_id, spec_cond in mask_map.items()),
        result
    )

    return result

def compute_anonymous_access_role_filter_q(conditional_role_masks, anonymous_role):
    result = False
    for filt_roles, filt_cond in conditional_role_masks:
        if isinstance(filt_roles, BackReference):
            return UnresolvedFilterRoles(filt_roles)
        if isinstance(filt_roles, (list, tuple)):
            # nested filter spec
            sub_result = compute_anonymous_access_role_filter_q(filt_roles)
            result = combine_or(result, combine_and(filt_cond, sub_result))
        elif filt_roles is None or (filt_roles & anonymous_role) != 0:
            result = combine_or(result, filt_cond)
    return result

def resolve_model(base_module, model):
    if not isinstance(model, str):
        return model

    if '.' in model:
        app_label, model_name = model.split('.')
    else:
        app_config = django_apps.get_containing_app_config(base_module)

        app_label = app_config.label
        model_name = model

    return django_apps.get_model(app_label, model_name)

def rewrite_expression(expression, annotation_names, fn_p, fn_a, prefix_map):
    def remap(identifier):
        head, sep, tail = identifier.partition(LOOKUP_SEP)
        if head == 'cur_user':
            return prefix_map['user'] + sep + tail
        head_a = fn_a(head)
        if head_a in annotation_names:
            return head_a + sep + tail
        return fn_p(head) + sep + tail
    
    def rewrite_q_item(item, depth):
        if not hasattr(item, 'resolve_expression'):
            arg, value = item
            return (remap(arg), rewrite(value, depth))
        return rewrite(item, depth)
    
    def rewrite(expression, depth):
        if isinstance(expression, models.FilteredRelation):
            new_expression = expression.clone()
            new_expression.relation_name = remap(new_expression.relation_name) # FIXME
            new_expression.condition = rewrite(new_expression.condition, depth)
            return new_expression
        if isinstance(expression, models.Q):
            return models.Q(*(rewrite_q_item(item, depth) for item in expression.children),
            _connector=expression.connector,
            _negated=expression.negated)
        if isinstance(expression, models.OuterRef):
            ref_name = expression.name
            ref_depth = 1
            while isinstance(ref_name, models.OuterRef):
                ref_name = ref_name.name
                ref_depth += 1
            if ref_depth != depth:
                return expression
            new_expression = models.OuterRef(remap(ref_name))
            for _ in range(1, ref_depth):
                new_expression = models.OuterRef(new_expression)
            return new_expression
        if isinstance(expression, models.F) and not isinstance(expression, models.OuterRef):
            if depth != 0:
                return expression
            return models.F(remap(expression.name)) if depth == 0 else expression
        if isinstance(expression, str):
            return models.F(remap(expression)) if depth == 0 else expression
        if not hasattr(expression, 'resolve_expression'):
            return expression
        if hasattr(expression, 'get_source_expressions'):
            old_source_expressions = expression.get_source_expressions()
            new_source_expressions = [rewrite(item, depth) for item in old_source_expressions]
            new_expression = copy.copy(expression)
            new_expression.set_source_expressions(new_source_expressions)
            return new_expression
        if isinstance(expression, Query):
            new_query = expression.clone()
            new_query.where = rewrite(new_query.where, depth + 1)
            new_query.annotations = {key: rewrite(value, depth + 1) for key, value in new_query.annotations}
            return new_query
        raise TypeError('cannot handle expression of type ' + type(expression).__name__)

    return rewrite(expression, 0)

def replace_condition_sentinels(conditions):
    special_roles = {}
    new_conditions = {}
    for role, expression in conditions.items():
        if expression in SPECIAL_ROLE_KEYS:
            if expression in special_roles:
                raise ValueError('multiple role value for ' + expression.__name__)
            special_roles[expression] = role
        else:
            new_conditions[role] = expression
    return new_conditions, special_roles

def rewrite_filter_roles(spec, annotation_names, fn_p, fn_a, prefix_map):
    def rewrite_filter_role_entry(item):
        if not isinstance(item, (list, tuple)):
            return item
        role, cond = item
        if isinstance(role, (list, tuple)):
            role = list(map(rewrite_filter_role_entry, value))
        if cond == models.Q():
            cond = True
        if cond == ~models.Q():
            cond = False
        cond = rewrite_expression(cond, annotation_names, fn_p, fn_a, prefix_map)
        return role, cond
    if not isinstance(spec, (list, tuple)):
        spec = [(spec, True)]
    return list(map(rewrite_filter_role_entry, spec))


class AccessAnnotateMixin:

    access_role_field = models.IntegerField()
    access_role_linked_models = ()
    access_role_prefix_id = None
    access_role_user_field_name = CONTEXT_USER_FIELD
    access_role_link_spec = {}

    @staticmethod
    def get_access_role_annotations(p, a, prefix_map):
        return {}

    @staticmethod
    def get_access_role_conditions(p, a, prefix_map):
        return {}

    @staticmethod
    def get_access_role_filter_roles(p, a, prefix_map, include, inherit):
        return inherit('*')

    @classmethod
    def _get_access_role_base_conditions(cls, special_roles):
        try:
            superuser_role = special_roles[Superuser]
        except KeyError:
            superuser_role = 0
        try:
            public_role = special_roles[NotSuperuser]
        except KeyError:
            public_role = 0
        user_masks = superuser_role | public_role
        user_field = cls.access_role_user_field_name
        if user_field == CONTEXT_USER_FIELD:
            user_qs = get_user_model()._base_manager.filter(pk=models.OuterRef(CONTEXT_USER_FIELD))
            superuser_cond = models.Exists(user_qs.filter(is_superuser=True))
            public_cond = models.Exists(user_qs.filter(is_superuser=False))
            anyuser_cond = models.Exists(user_qs)
        else:
            superuser_cond = models.Q(**{ user_field + '__is_superuser': True })
            public_cond = models.Q(**{ user_field + '__is_superuser': False })
            anyuser_cond = models.Q(**{ user_field + '__isnull': False })
        lookup_table = {}
        if superuser_role:
            lookup_table[superuser_role] = superuser_cond
        if public_role:
            lookup_table[public_role] = public_cond
        if superuser_role and public_role:
            lookup_table[superuser_role | public_role] = anyuser_cond
        if not lookup_table:
            return {}
        return {
            user_masks: SimpleConditionGroup(
                lookup_table=lookup_table,
                basis=tuple(filter(None, (superuser_role, public_role))),
            )
        }

    @classmethod
    def _collect_access_role_linked_models(cls, model):
        linked_models = OrderedDict()
        link_spec = {}
        source_modules = {}
        for model_base_cls in reversed(model.__mro__):
            if not issubclass(model_base_cls, AccessControlledModelMixin):
                continue
            for model, alias in getattr(model_base_cls, 'role_linked_models', ()):
                source_modules[alias] = model_base_cls.__module__
                if model is None:
                    linked_models.pop(alias, None)
                else:
                    linked_models[alias] = model
            for alias, spec in getattr(model_base_cls, 'role_link_spec', {}).items():
                source_modules[alias] = model_base_cls.__module__
                link_spec.setdefault(alias, {}).update(spec)
        for base_cls in reversed(cls.__mro__):
            if not issubclass(base_cls, AccessAnnotateMixin):
                continue
            for model, alias in base_cls.access_role_linked_models:
                source_modules[alias] = base_cls.__module__
                if model is None:
                    linked_models.pop(alias, None)
                else:
                    linked_models[alias] = model
            for alias, spec in base_cls.access_role_link_spec.items():
                source_modules[alias] = base_cls.__module__
                link_spec.setdefault(alias, {}).update(spec)
        return [
            (source_modules[alias], model, alias, link_spec.get(alias, {}))
            for alias, model in linked_models.items()
        ]

    @classmethod
    def _compute_access_role_expressions(cls, model, prefix, annotation_prefix,
                                         prefix_map):
        if cls in prefix_map:
            raise RecursionError('loop detected in access_role_linked_models')

        fn_p = lambda ident: prefix + ident
        fn_a = lambda ident: annotation_prefix + ident

        try:
            model_annotations = model.role_annotations
        except AttributeError:
            model_annotations = {}

        try:
            model_conditions = model.role_conditions
        except AttributeError:
            model_conditions = {}

        annotation_names = set(map(fn_a, model_annotations.keys()))
        annotations = {}
        annotations.update({
            fn_a(name): rewrite_expression(expression, annotation_names, fn_p, fn_a, prefix_map)
            for name, expression in model_annotations.items()
        })
        annotations.update(cls.get_access_role_annotations(fn_p, fn_a, prefix_map))

        annotation_names = annotations.keys()
        conditions = {}
        conditions.update(cls.get_access_role_conditions(fn_p, fn_a, prefix_map))
        model_conditions, special_roles = replace_condition_sentinels(model_conditions)
        conditions.update({
            role: rewrite_expression(expression, annotation_names, fn_p, fn_a, prefix_map)
            for role, expression in model_conditions.items()
        })
        parent_filter_roles = {}

        prefix_id = cls.access_role_prefix_id
        if prefix_id is not None:
            prefix_map = {
                **prefix_map,
                prefix_id: {'p': fn_p, 'a': fn_a}
            }

        for (source_module, linked_model, alias, spec), annotation_alias in zip(
                    cls._collect_access_role_linked_models(model),
                    generate_alphabet_sequence()):
            if isinstance(linked_model, BackModelReference):
                parent_filter_roles[alias] = linked_model
                continue

            manager_name = spec.get('manager', '_default_manager')

            linked_model = resolve_model(source_module, linked_model)
            manager = getattr(linked_model, manager_name)

            sub_annotations, sub_conditions, sub_filter_roles, sub_special_roles = (
                manager.all()._compute_access_role_expressions(
                    linked_model,
                    prefix=(
                        (annotation_prefix
                         if spec.get('is_annotation') else
                         prefix) +
                        alias + LOOKUP_SEP
                    ),
                    annotation_prefix=(
                        annotation_prefix + annotation_alias + '_'
                    ),
                    prefix_map=prefix_map
                )
            )
            if any(key in special_roles and key in sub_special_roles and
                       special_roles[key] != sub_special_roles[key]
                       for key in SPECIAL_ROLE_KEYS):
                raise ValueError('current model\'s special roles are not subset of parent special roles')
            special_roles.update(sub_special_roles)
            annotations.update(sub_annotations)
            for flag, cond in sub_conditions.items():
                if flag in conditions:
                    conditions[flag] |= cond
                else:
                    conditions[flag] = cond
            parent_filter_roles[alias] = sub_filter_roles

        def normalize_parents_ref(parents, require_key=None):
            if not isinstance(parents, str):
                return list(parents)
            if parents == '*':
                parents = parent_filter_roles.keys()
                if require_key is None:
                    return list(parents)
                return [k for k, v in parents.items() if require_key in v]
            return [parents]

        def include(parents, name, only_roles=None):
            result = []
            parents = normalize_parents_ref(parents, name)
            for parent_name in parents:
                specmap = parent_filter_roles[parent_name]
                if isinstance(specmap, BackModelReference):
                    ref = BackReference(
                            specmap.prefix_id, name, only_roles=only_roles)
                    result.append((ref, True))
                    continue
                for role, condition in specmap[name]:
                    if only_roles is not None:
                        role = (
                            role & only_roles
                            if role is not None else
                            only_roles
                        )
                    result.append((role, condition))
            return result

        def inherit(parents):
            result = {}
            for parent_name in normalize_parents_ref(parents):
                value = parent_filter_roles[parent_name]
                if not isinstance(value, BackModelReference):
                    result.update(value)
            return result

        filter_roles = {}
        filter_roles.update(
            cls.get_access_role_filter_roles(fn_p, fn_a, prefix_map,
                                             include=include,
                                             inherit=inherit)
        )
        filter_roles.update({
            name: rewrite_filter_roles(spec, annotation_names, fn_p, fn_a, prefix_map)
            for name, spec in getattr(model, 'role_permissions', {}).items()
        })

        def flatten_filter_roles(spec):
            for item in spec:
                role, cond = item
                if isinstance(role, (list, tuple)) and cond is True:
                    yield from flatten_filter_roles(role)
                else:
                    yield item

        def normalize_filter_roles(spec):
            while isinstance(spec, BackReference):
                if spec.prefix_id != prefix_id or spec.name not in filter_roles:
                    return spec
                spec = filter_roles[spec.name]
            result = OrderedDict()
            for role, condition in flatten_filter_roles(spec):
                if isinstance(role, (list, tuple, BackReference)):
                    role = normalize_filter_roles(role)
                result[(role, condition)] = None
            return tuple(result.keys())

        filter_roles = {
            name: normalize_filter_roles(spec)
            for name, spec in filter_roles.items()
        }

        return annotations, conditions, filter_roles, special_roles

    @classmethod
    def _get_access_role_expresions(cls, model):
        try:
            return cls.__dict__['_cached_access_role_expressions']
        except KeyError:
            pass

        annotations, conditions, filter_roles, special_roles = (
            cls._compute_access_role_expressions(
                model=model,
                prefix='',
                annotation_prefix='',
                prefix_map={
                    'user': cls.access_role_user_field_name
                }
            )
        )

        base_conditions = cls._get_access_role_base_conditions(special_roles)
        if any(key in conditions for key in base_conditions):
            raise RuntimeError('conditions not disjoint with base')
        conditions.update(base_conditions)

        filter_roles = {
            key: (
                compute_access_role_filter_q(
                    conditions,
                    preoptimize_nested_conditional_role_masks(value),
                ),
                compute_anonymous_access_role_filter_q(
                    value,
                    special_roles[Anonymous],
                ),
            )
            for key, value in filter_roles.items()
        }

        result = annotations, conditions, filter_roles, special_roles
        cls._cached_access_role_expressions = result
        return result

    @classmethod
    def _get_current_access_role_annotations(cls, model):
        return cls._get_access_role_expresions(model)[0]

    @classmethod
    def _get_current_access_role_conditions(cls, model):
        return cls._get_access_role_expresions(model)[1]

    @classmethod
    def _get_current_access_role_filter_q_dict(cls, model):
        return cls._get_access_role_expresions(model)[2]

    @classmethod
    def _get_current_access_role_special_roles(cls, model):
        return cls._get_access_role_expresions(model)[3]

    @classmethod
    def _get_filter_q(cls, model, name, is_anonymous):
        return cls._get_current_access_role_filter_q_dict(model)[name][is_anonymous]

    @classmethod
    def _get_current_access_role_expr(cls, model):
        try:
            return cls.__dict__['_cached_access_role_expr']
        except KeyError:
            pass

        # NOTE This function is not in hot path itself, but the resolution of
        # NOTE subsequent expressions is.  Save output_field resolution time
        # NOTE by resolving them early.
        role_conditions = cls._get_current_access_role_conditions(model)
        output_field = cls.access_role_field
        zero = models.Value(0, output_field=output_field)
        expr = None
        for flag, cond in flatten_condition_map(role_conditions):
            flag_val = models.Value(flag, output_field=output_field)
            cur_expr = models.Case(
                models.When(cond, flag_val),
                default=zero, output_field=output_field
            )
            expr = cur_expr if expr is None else expr.bitor(cur_expr)

        cls._cached_access_role_expr = expr
        return expr

    # FIXME filter_q is workaround for Django bug duplicating LEFT OUTER JOIN
    # FIXME when an annotation is specified ealier than a filter, both using
    # FIXME the FilteredRelation.
    # FIXME Example: qs.annotate(fr=FR()).annotate(x=fr__v).filter(fr__j=1)
    def annotate_current_access(self, user, *,
                                use_roles_field=True,
                                current_time=None,
                                filter_roles=None,
                                filter_q=None,
                                alias_role_conds={}):
        is_empty = False
        annotations = None
        role_q = True
        if current_time is None:
            current_time = timezone.now()
        if user is not None:
            UserModel = get_user_model()
            if isinstance(user, UserModel):
                user = user.pk
            if not hasattr(user, 'resolve_expression'):
                user = models.Value(user, output_field=UserModel._meta.pk)
            if not hasattr(current_time, 'resolve_expression'):
                current_time = models.Value(current_time,
                                            output_field=models.DateTimeField())
            qs = self.alias(**{ CURRENT_TIME_FIELD: current_time })
            if use_roles_field:
                acc_expr = self._get_current_access_role_expr(self.model)
            if models.F(self.access_role_user_field_name) != user:
                user_annotations = { self.access_role_user_field_name: user }
                qs = (
                    qs.annotate(**user_annotations)
                    if use_roles_field else
                    qs.alias(**user_annotations)
                )
            if use_roles_field or filter_roles is not None:
                qs = qs.annotate(**self._get_current_access_role_annotations(self.model))
        else:
            qs = self
            if use_roles_field:
                anonymous_role = self._get_current_access_role_special_roles(self.model).get(Anonymous, 0)
                acc_expr = models.Value(anonymous_role, output_field=self.access_role_field)

        is_anonymous = user is None
        if filter_roles is not None:
            role_q = self._get_filter_q(self.model, filter_roles, is_anonymous=is_anonymous)

        if role_q is False:
            qs = qs.none()
        elif filter_q is not None and role_q is not True:
            qs = qs.filter(filter_q & role_q)
        elif filter_q is not None or role_q is not True:
            qs = qs.filter(filter_q if role_q is True else role_q)

        if alias_role_conds:
            qs = qs.alias(**{
                key: wrap_condition(
                    self._get_filter_q(self.model, value, is_anonymous=is_anonymous)
                )
                for key, value in alias_role_conds.items()
            })

        if use_roles_field:
            qs = qs.annotate(**{ACCESS_ROLE_FIELD: acc_expr})
        return qs
    
    def filter_by_access(self, user, permission):
        return self.annotate_current_access(user, filter_roles=permission)

    def annotate_dummy_access(self):
        acc_expr = models.Value(None, output_field=self.access_role_field)
        return self.annotate(**{ACCESS_ROLE_FIELD: acc_expr})


class AccessControlledModelMixin:

    def get_access_roles(self, user, default=0, using=None):
        if user is None:
            return self.__class__._default_manager.all()._get_current_access_role_special_roles(self.__class__).get(Anonymous, 0)
        if isinstance(user, models.Model):
            user = user.pk
        try:
            ctx_user = getattr(self, CONTEXT_USER_FIELD)
            cache_exists = True
        except AttributeError:
            cache_exists = False
        if cache_exists and ctx_user == user:
            access_role = getattr(self, ACCESS_ROLE_FIELD)
        else:
            qs = self.__class__._default_manager.db_manager(using=using) \
                .order_by().filter(pk=self.pk).annotate_current_access(user)
            try:
                ctx_user, access_role = qs.values_list(
                    CONTEXT_USER_FIELD, ACCESS_ROLE_FIELD).get()
            except qs.model.DoesNotExist:
                # TODO really cache negative?
                ctx_user = user
                access_role = None
            else:
                if ctx_user != user:
                    raise InconsistentDatabaseValuesError(CONTEXT_USER_FIELD)
            if not cache_exists:
                setattr(self, CONTEXT_USER_FIELD, ctx_user)
                setattr(self, ACCESS_ROLE_FIELD, access_role)
        if access_role is None:
            return default
        return access_role

    def invalidate_access_roles_cache(self, user=None):
        if user is not None:
            if isinstance(user, models.Model):
                user = user.pk
            try:
                ctx_user = getattr(self, CONTEXT_USER_FIELD)
            except AttributeError:
                return
            if ctx_user != user:
                return
        try:
            delattr(self, CONTEXT_USER_FIELD)
        except AttributeError:
            pass
        try:
            delattr(self, ACCESS_ROLE_FIELD)
        except AttributeError:
            pass

_name_counter = 0
def create_queryset_class():
    global _name_counter
    _name_counter += 1 # FIXME potential race condition
    name = 'AccessAnnotatedQuerySet' + str(_name_counter)
    cls = type(name, (AccessAnnotateMixin, models.QuerySet), {})  # FIXME use proper class instantiaton method
    return cls

def create_manager_class():
    return create_queryset_class().as_manager()