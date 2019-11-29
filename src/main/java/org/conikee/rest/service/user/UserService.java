package org.conikee.rest.service.user;

import org.conikee.rest.domain.User;
import org.conikee.rest.domain.UserCreateForm;

import java.util.Collection;
import java.util.Optional;


public interface UserService {

    Optional<User> getUserById(long id);

    Optional<User> getUserByEmail(String email);

    Collection<User> getAllUsers();

    User create(UserCreateForm form);

}
