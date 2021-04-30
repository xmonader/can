from can import *

def test_basic():
    memrbac = MemBackend()
    rbac = RBAC(memrbac)

    create_post = rbac.create_permission("create_post")
    read_post = rbac.create_permission("read_post")
    update_post = rbac.create_permission("update_post")
    lock_post = rbac.create_permission("lock_post")
    delete_post = rbac.create_permission("delete_post")

    post_mgmt = rbac.create_role("post_mgmt")
    
    guest = rbac.create_role("guest")
    user = rbac.create_role("user")
    moderator = rbac.create_role("moderator")

    rbac.add_many([create_post, read_post,update_post, lock_post, delete_post, post_mgmt, guest, user, moderator])

    rbac.add_child(guest, read_post)
    rbac.add_children(user, [create_post, guest])


    rbac.add_children(post_mgmt, [create_post, read_post,update_post,delete_post, lock_post])
    rbac.add_children(moderator, [post_mgmt])

    assert rbac.can("guest", "read_post") == True
    assert rbac.can("guest", "create_post") == False
    assert rbac.can("guest", "update_post") == False
    assert rbac.can("guest", "delete_post") == False
    assert rbac.can("guest", "lock_post") == False


    assert rbac.can("user", "read_post") == True
    assert rbac.can("user", "create_post") == True
    assert rbac.can("user", "update_post") == False
    assert rbac.can("user", "delete_post") == False
    assert rbac.can("user", "lock_post") == False

    assert rbac.can("moderator", "read_post") == True
    assert rbac.can("moderator", "create_post") == True
    assert rbac.can("moderator", "update_post") == True
    assert rbac.can("moderator", "delete_post") == True
    assert rbac.can("moderator", "lock_post") == True


    USERS = {1: {"name":"ahmed"}, 2:{"name":"notahmed"}}

    rbac.assign(1, moderator)
    rbac.assign(2, user)

    assert rbac.can_user(1, "read_post") == True
    assert rbac.can_user(1, "create_post") == True
    assert rbac.can_user(1, "update_post") == True
    assert rbac.can_user(1, "delete_post") == True
    assert rbac.can_user(1, "lock_post") == True


    assert rbac.can_user(2, "read_post") == True
    assert rbac.can_user(2, "create_post") == True
    assert rbac.can_user(2, "update_post") == False
    assert rbac.can_user(2, "delete_post") == False
    assert rbac.can_user(2, "lock_post") == False


    # let's add another permission to updateOwnPost
    update_own_post = rbac.create_permission("update_own_post")
    class UpdateOwnPostRule(Rule):
        def check(self, uid, item, payload):
            if payload["author_id"] == uid:
                return True
            return False

    update_own_post_rule = UpdateOwnPostRule(name="update_own_post_rule", description="user can only update their own posts.")
    update_own_post.rule_name = "update_own_post_rule"
    rbac.add(update_own_post)
    rbac.add(update_own_post_rule)
    rbac.add_child(update_own_post, update_post)
    rbac.add_child(user, update_own_post)

    posts = {
       1: {"id": 1, "author_id":1, "title": "hello world!", "text": "my first post"},
       2: {"id": 2, "author_id":2, "title": "wassup!", "text": "my first post"},
       3: {"id": 3, "author_id":2, "title": "hey now!", "text": "my 2nd post post"}, 
    }
    assert rbac.can_user(1, "read_post", posts[1] ) == True
    assert rbac.can_user(1, "read_post", posts[2] ) == True
    assert rbac.can_user(1, "read_post", posts[3] ) == True

    assert rbac.can_user(1, "read_post", posts[1] ) == True
    assert rbac.can_user(1, "read_post", posts[2] ) == True
    assert rbac.can_user(1, "read_post", posts[3] ) == True

    assert rbac.can_user(1, "update_post", posts[1]) == True
    assert rbac.can_user(1, "update_post", posts[2]) == True
    assert rbac.can_user(1, "update_post", posts[3]) == True

    assert rbac.can_user(2, "update_own_post", posts[1]) == False
    assert rbac.can_user(2, "update_own_post", posts[2]) == True
    assert rbac.can_user(2, "update_own_post", posts[3]) == True