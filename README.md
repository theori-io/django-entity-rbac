# Django Entity-Relationship-based Access Control

django-entity-rbac is an implementation of Entity-Relationship-based Access Control for Django.

This project attempts to satisfy the follow requirements:

* Table-less role assignment
* Elimination of [the role explosion problem][role-explosion]
* Hierarchical object graphs
* Row-level access control

**django-entity-rbac is currently under heavy development.**


## Authors
Minkyo Seo ([@0xsaika](https://github.com/0xsaika)), Jinoh Kang ([@iamahuman](https://github.com/iamahuman))

## Quick start
Compatible with Django 3.x.
```
pip install django-entity-rbac
```

## Usage
See [`roletestapp`](https://github.com/theori-io/django-entity-rbac/tree/main/roletestapp)

## Documentation
TODO

[PyCon 2022 talk](https://2022.pycon.kr/program/talks/26)

## Roadmap
 - [x] Release unstable API (v0.1) as proof-of-concept (kudos to Jinoh)
 - [ ] Improve API usability
    - [ ] Redesign internal APIs
    - [ ] Add separate permission spec classes for compose-able role declaration
    - [ ] Replace bit fields with something less error-prone and foolproof
 - [ ] Release stable v1

## License
django-entity-rbac is licensed under the MIT license.

[role-explosion]: https://blog.plainid.com/role-explosion-unintended-consequence-rbac
