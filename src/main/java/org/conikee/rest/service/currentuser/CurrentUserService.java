package org.conikee.rest.service.currentuser;

import org.conikee.rest.domain.CurrentUser;

public interface CurrentUserService {

    boolean canAccessUser(CurrentUser currentUser, Long userId);

}
