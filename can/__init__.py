from dataclasses import dataclass, field
from typing import Union, Any, List, Optional
from collections import defaultdict

@dataclass
class AuthItem:
    name: str
    description: str = ""


@dataclass
class Rule(AuthItem):
    def check(self, uid, item, payload):
        return False

class NOOPRule(Rule):
    def check(self, uid, item, payload):
        return True


    rule_name: str = ""

@dataclass
class Ruleable(AuthItem):
    rule_name: str = ""
    subitems: list = field(default_factory=list)

@dataclass
class Permission(Ruleable):
    pass

@dataclass
class Role(Ruleable):
    pass


class MemBackend:
    def __init__(self):
        self.roles = {}
        self.perms = {}
        self.rules = {}
        self.assignments = {}

    def add(self, obj: Union[Permission,Role, Rule]):
        if isinstance(obj, Role):
            self.roles[obj.name] = obj
        elif isinstance(obj, Permission):
            self.perms[obj.name] = obj
        elif isinstance(obj, Rule):
            self.rules[obj.name] = obj

    def add_many(self, items: List[Union[Permission,Role, Rule]]):
        for item in items:
            self.add(item)

    def add_child(self, ruleable: Ruleable, obj: Union[Permission,Role]):
        if ruleable.name in self.roles:
            self.roles[ruleable.name].subitems.append(obj)
        if ruleable.name in self.perms:
            self.perms[ruleable.name].subitems.append(obj)
            

    def can(self, role: str, what:str):
        what_is_perm = what in self.perms
        what_is_role = what in self.roles
        root_role_name = role
        if root_role_name not in self.roles.keys():
            return False
        else:
            for item in self.roles[root_role_name].subitems:
                print(f"item is {item} and what is {what}")
                if what_is_perm and item.name == what:
                    return True
                elif what_is_role and item.name == what:
                    return True
                else:
                    if isinstance(item, Role):
                        print(f"recursing into {item.name}")
                        return self.can(item.name, what) # search recursively
            return False

    def assign(self, uid, item):
        if uid not in self.assignments:
            self.assignments[uid] = []
        
        self.assignments[uid].append(item)


    def _can_do(self, uid, item, what, payload):
        rule = NOOPRule("noop")
        if item.name == what:
            if item.rule_name:
                rule = self.rules[item.rule_name]
            return rule.check(uid, item, payload)
        else:
            for sub in item.subitems:
                if self._can_do(uid, sub, what, payload):
                    return True
        
        return False

    def can_user(self, uid: int, what: str, payload:Optional[Any]=None, item=None):
        for item in self.assignments[uid]:
            print("item is ...: ", item)
            if self._can_do(uid, item, what, payload):
                return True
        return False              


class RBAC:
    def __init__(self, backend):
        self.backend = backend

    def create_permission(self, name, description=""):
        return Permission(name, description)

    def create_role(self, name, description=""):
        return Role(name, description, subitems=[])
    
    def add(self, obj: Union[Permission,Role, Rule]):
        return self.backend.add(obj)

    def add_many(self, items: List[Union[Permission,Role, Rule]]):
        self.backend.add_many(items)

    def add_child(self, ruleable: Ruleable, obj: Union[Permission, Role]):
        self.backend.add_child(ruleable, obj)

    def add_children(self, ruleable: Ruleable, items: List[Union[Permission, Role]]):
        for el in items:
            self.add_child(ruleable, el)
    
    def assign(self, uid, item):
        self.backend.assign(uid, item)


    def can(self, role: str, what:str):
        return self.backend.can(role, what)
    
    def can_user(self, uid: int, what: str, payload: Any=None):
        return self.backend.can_user(uid, what, payload)

