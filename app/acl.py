#OWASP 1
# Access control list

# Rolle basert access control:
# Systemet skal assigne rolle til en bruker og fjerne en bruker fra denne rollen
# inputs er USER, ACTION TYPE, RESOURCE, ROLE
# ACTION TYPE definnerer access level (_read, _write, _delete)
# Access til brukere er bestemt av rollen deres, og en bruker kan ha flere roller
# systemet skal kunne fortelle om en bruker har tilgang eller ikke til å utføre ACTION TYPE
from models import Role, User

everyone_role = Role('everyone')
admin_role = Role('admin')

everyone_user = User(roles=[everyone_role])
admin_user = User(roles=[admin_role, everyone_role])

class AccessControlList(object):
    # Definerer access control regler
    # Dersom en rolle ikke er gitt, rule of least privileges

    def __init__(self):
        self._read = []
        self._write = []
        self._delete = []

    def resource_read_rule(self, role, method, resource):
        # Legger til read access
        # role: Rolen til denne regelen
        # method: REST verbs allowed to access resource. Include GET, PUT et al.
        # resource: The resource in question
        
        permission = (role.get_name(), method, resource)
        if permission not in self._read:
            self._read.append(permission)

    def resource_write_rule(self, role, method, resource):
        # Legger til write access
        # role: Rolen til denne regelen
        # method: REST verbs allowed to access resource. Include GET, PUT et al.
        # resource: The resource in question

        permission = (role.get_name(), method, resource)
        if permission not in self._write:
            self._write.append(permission)

    def resource_delete_rule(self, role, method, resource):
        # Legger till full access
        
        # role: Rolen til denne regelen
        # method: REST verbs allowed to access resource. Include GET, PUT et al.
        # resource: The resource in question
        
        permission = (role.get_name(), method, resource)
        if permission not in self._delete:
            self._delete.append(permission)

    def is_read_allowed(self, role, method, resource):
        # Returnerer om denne rollen har READ access: Boolean
        return (role, method, resource) in self._read

    def is_write_allowed(self, role, method, resource):
        # Returnerer om denne rollen har WRITE access: Boolean
        return (role, method, resource) in self._write

    def is_delete_allowed(self, role, method, resource):
        # Returnerer om denne rollen har DELEAT access: Boolean
        return (role, method, resource) in self._delete


acl = AccessControlList()
acl.resource_read_rule(everyone_role, 'GET', '/api/v1/employee/1/info')
acl.resource_delete_rule(admin_role, 'DELETE', '/api/v1/employee/1/')

# checking READ operation on resource for user `everyone_user`
for user_role in [role.get_name() for role in everyone_user.get_roles()]:
    assert acl.is_read_allowed(user_role, 'GET', '/api/v1/employee/1/info') == True

# checking WRITE operation on resource for user `everyone_user`
# Since you have not defined the rule for the particular, it will disallow any such operation by default.
for user_role in [role.get_name() for role in everyone_user.get_roles()]:
    assert acl.is_write_allowed(user_role, 'WRITE', '/api/v1/employee/1/info') == False

# checking WRITE operation on resource for user `admin_user`
for user_role in [role.get_name() for role in everyone_user.get_roles()]:
    if user_role == 'admin': # as a user can have more than one role assigned to them
        assert acl.is_delete_allowed(user_role, 'DELETE', '/api/v1/employee/1/') == True
    else:
        assert acl.is_delete_allowed(user_role, 'DELETE', '/api/v1/employee/1/') == False