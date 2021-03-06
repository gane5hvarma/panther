/**
 * Panther is a scalable, powerful, cloud-native SIEM written in Golang/React.
 * Copyright (C) 2020 Panther Labs Inc
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

import React from 'react';
import Auth, { CognitoUser } from '@aws-amplify/auth';
import { USER_INFO_STORAGE_KEY } from 'Source/constants';
import storage from 'Helpers/storage';
import { RoleNameEnum } from 'Generated/schema';

// Challenge names from Cognito from
// https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_RespondToAuthChallenge.html#API_RespondToAuthChallenge_RequestSyntax
export enum CHALLENGE_NAMES {
  MFA_SETUP = 'MFA_SETUP',
  NEW_PASSWORD_REQUIRED = 'NEW_PASSWORD_REQUIRED',
  SOFTWARE_TOKEN_MFA = 'SOFTWARE_TOKEN_MFA',
}

interface AuthError {
  /** unique error code */
  code: string;

  /** verbose exception that happened */
  message: string;

  /** optional | name of the exception, usually just the code itself */
  name?: string;
}

interface EnhancedCognitoUser extends CognitoUser {
  challengeParam: {
    userAttributes: {
      email: string;
      given_name?: string;
      family_name?: string;
    };
  };
  challengeName?: CHALLENGE_NAMES;
  attributes: {
    email: string;
    email_verified: boolean;
    family_name?: string;
    given_name?: string;
    sub: string;
  };
  signInUserSession?: {
    accessToken?: {
      payload: {
        'cognito:users'?: RoleNameEnum[];
      };
    };
  };
}

export type UserInfo = EnhancedCognitoUser['attributes'] & {
  roles: RoleNameEnum[];
};

interface SignOutParams {
  global?: boolean;
  onSuccess?: () => void;
  onError?: (err: AuthError) => void;
}

interface SignInParams {
  username: string;
  password: string;
  onSuccess?: () => void;
  onError?: (err: AuthError) => void;
}

interface ConfirmSignInParams {
  mfaCode: string;
  onSuccess?: () => void;
  onError?: (err: AuthError) => void;
}

interface VerifyTotpSetupParams {
  mfaCode: string;
  onSuccess?: () => void;
  onError?: (err: AuthError) => void;
}

interface SetNewPasswordParams {
  newPassword: string;
  onSuccess?: () => void;
  onError?: (err: AuthError) => void;
}

interface UpdateUserInfoParams {
  newAttributes: Partial<EnhancedCognitoUser['attributes']>;
  onSuccess?: () => void;
  onError?: (err: AuthError) => void;
}

interface ChangePasswordParams {
  oldPassword: string;
  newPassword: string;
  onSuccess?: () => void;
  onError?: (err: AuthError) => void;
}

interface ResetPasswordParams {
  token: string;
  email: string;
  newPassword: string;
  onSuccess?: () => void;
  onError?: (err: AuthError) => void;
}

interface ForgotPasswordParams {
  email: string;
  onSuccess?: () => void;
  onError?: (err: AuthError) => void;
}

/*
  We intentionaly use `undefined` and `null` in the interface below to showcase the possible values
 */
export interface AuthContextValue {
  isAuthenticated: boolean | undefined;
  currentAuthChallengeName: CHALLENGE_NAMES | null;
  userInfo: UserInfo | null;
  signIn: (params: SignInParams) => Promise<void>;
  confirmSignIn: (params: ConfirmSignInParams) => Promise<void>;
  setNewPassword: (params: SetNewPasswordParams) => Promise<void>;
  verifyTotpSetup: (params: VerifyTotpSetupParams) => Promise<void>;
  requestTotpSecretCode: () => Promise<string>;
  signOut: (params?: SignOutParams) => Promise<void>;
  updateUserInfo: (params: UpdateUserInfoParams) => Promise<void>;
  changePassword: (params: ChangePasswordParams) => Promise<void>;
  resetPassword: (params: ResetPasswordParams) => Promise<void>;
  forgotPassword: (params: ForgotPasswordParams) => Promise<void>;
}

const AuthContext = React.createContext<AuthContextValue>(undefined);

// We check if there was a previous session for this user already present. We use that to
// *OPTIMISTICALLY* decide whether the user should be considered authenticated on mount time. We
// say optimistically as the token may have expired by the time they revisit. This will be handled
// in the Amplify, since the `isAuthenticated` flag just decides which screens to show.
const previousUserSessionExists = Boolean(
  storage.read(
    `CognitoIdentityServiceProvider.${process.env.AWS_COGNITO_APP_CLIENT_ID}.LastAuthUser`
  )
);

const AuthProvider: React.FC = ({ children }) => {
  // Stores whether the system should consider the current user as logged-in or not. This can be
  // true without `authUser` being present, since `authUser` comes asynchronously from Cognito, thus
  // it's *always* initially `null`.
  const [isAuthenticated, setAuthenticated] = React.useState(previousUserSessionExists);
  // Stores the currently authenticated user of the app
  const [authUser, setAuthUser] = React.useState<EnhancedCognitoUser | null>(null);

  /*
   * Isolate the userInfo from the user. This is an object that will persist in our storage so that
   * we can boot up the user's information (name, roles, etc.) the next time he visits the app. The
   * value changes whenever the cognito session changes
   */
  const userInfo = React.useMemo<UserInfo>(() => {
    // if a user is present, derive the user info from him
    if (authUser) {
      return {
        ...authUser.attributes,
        roles: authUser?.signInUserSession?.accessToken.payload['cognito:groups'] || [],
      };
    }

    // if no user is present, attempt to return data from the stored session. This is true when
    // the request to get the cognito `authUser` is in flight and hasn't returned yet
    if (isAuthenticated) {
      return storage.read<UserInfo>(USER_INFO_STORAGE_KEY);
    }

    // if no prev session exists and the user is not logged-in, then there is no userInfo
    return null;
  }, [isAuthenticated, authUser]);

  /**
   * Every time the `userInfo` is updated, we want to store this value in our storage in order to
   * remember it for future logins. If we don't do that, then we don't have a way of knowing the
   * "roles" of the user on mount time. This means that the user might see a flash of 403 or 404
   * since we are not yet sure of whether he/she has access to see this page/component or not
   */
  React.useEffect(() => {
    if (userInfo) {
      storage.write(USER_INFO_STORAGE_KEY, userInfo);
    } else {
      storage.delete(USER_INFO_STORAGE_KEY);
    }
  }, [userInfo]);

  /**
   * @public
   * Signs the user in our system
   *
   */
  const signIn = React.useCallback(
    async ({ username, password, onSuccess = () => {}, onError = () => {} }: SignInParams) => {
      try {
        const signedInUser = await Auth.signIn(username, password);
        setAuthUser(signedInUser);

        onSuccess();
      } catch (err) {
        onError(err as AuthError);
      }
    },
    []
  );

  /**
   * @public
   * Signs the user out. Can be global sign out (all devices) or just local (this device only)
   *
   */
  const signOut = React.useCallback(
    ({ global = false, onSuccess = () => {}, onError = () => {} }: SignOutParams = {}) => {
      return Auth.signOut({ global })
        .then(onSuccess)
        .catch(onError)
        .finally(() => {
          setAuthUser(null);
          setAuthenticated(false);
        });
    },
    []
  );

  /**
   *
   * @public
   * Verifies that the user is not an imposter by verifying the TOTP challenge that the user was
   * presented with. This function verifies that the one-time password was indeed correct
   *
   */
  const confirmSignIn = React.useCallback(
    async ({ mfaCode, onSuccess = () => {}, onError = () => {} }: ConfirmSignInParams) => {
      try {
        await Auth.confirmSignIn(authUser, mfaCode, 'SOFTWARE_TOKEN_MFA');

        const confirmedUser = await Auth.currentAuthenticatedUser();
        setAuthUser(confirmedUser);
        setAuthenticated(true);

        onSuccess();
      } catch (err) {
        onError(err as AuthError);
      }
    },
    [authUser]
  );

  /**
   *
   * @public
   * Verifies that the user has correctly setup the TOTP
   *
   */
  const verifyTotpSetup = React.useCallback(
    async ({ mfaCode, onSuccess = () => {}, onError = () => {} }: VerifyTotpSetupParams) => {
      try {
        await Auth.verifyTotpToken(authUser, mfaCode);
        await Auth.setPreferredMFA(authUser, 'TOTP');

        const userWithMFA = await Auth.currentAuthenticatedUser();
        setAuthUser(userWithMFA);

        onSuccess();
      } catch (err) {
        onError(err as AuthError);
      }
    },
    [authUser]
  );

  /**
   *
   * @public
   * Updates the user's personal information
   *
   */
  const updateUserInfo = React.useCallback(
    async ({ newAttributes, onSuccess = () => {}, onError = () => {} }: UpdateUserInfoParams) => {
      try {
        await Auth.updateUserAttributes(authUser, newAttributes);
        const updatedUser = await Auth.currentAuthenticatedUser({ bypassCache: true });
        setAuthUser(updatedUser);

        onSuccess();
      } catch (err) {
        onError(err as AuthError);
      }
    },
    [authUser]
  );

  /**
   * @public
   * Sets up TOTP for the user by requesting a new secret code to be used as part of the oauth url
   */
  const requestTotpSecretCode = React.useCallback(() => Auth.setupTOTP(authUser), [authUser]);

  /**
   * @public
   * Sets a new password for the user when he has a temporary one
   *
   */
  const setNewPassword = React.useCallback(
    async ({ newPassword, onSuccess = () => {}, onError = () => {} }: SetNewPasswordParams) => {
      try {
        const userWithUpdatedPassword = await Auth.completeNewPassword(authUser, newPassword, {});

        // simply clone it (that's what this code does) so the ref changes in order to trigger
        // a React re-render (amplify mutates while react plays with immutable structures)
        setAuthUser(
          Object.assign(
            Object.create(Object.getPrototypeOf(userWithUpdatedPassword)),
            userWithUpdatedPassword
          )
        );

        onSuccess();
      } catch (err) {
        onError(err as AuthError);
      }
    },
    [authUser]
  );

  /**
   * @public
   * Changes the current password for the user. This is a different workflow than `setPassword`,
   * since the user doesn't have a temporary password here and he also needs to provide his old
   * password
   */
  const changePassword = React.useCallback(
    async ({
      oldPassword,
      newPassword,
      onSuccess = () => {},
      onError = () => {},
    }: ChangePasswordParams) => {
      try {
        await Auth.changePassword(authUser, oldPassword, newPassword);

        onSuccess();
      } catch (err) {
        onError(err as AuthError);
      }
    },
    [authUser]
  );

  /**
   * @public
   * Resets the current password for the user to the value he has given. This is a different
   * workflow than `setPassword` or `changePassword` since the user doesn't have knowledge of his
   * current password, except for a reset link that he received through an email. This link
   * contained the reset token used below
   */
  const resetPassword = React.useCallback(
    async ({
      email,
      token,
      newPassword,
      onSuccess = () => {},
      onError = () => {},
    }: ResetPasswordParams) => {
      try {
        await Auth.forgotPasswordSubmit(email, token, newPassword);

        onSuccess();
      } catch (err) {
        onError(err as AuthError);
      }
    },
    []
  );

  /**
   * @public
   * A method to initiate a forgot password request. This will send the user an email containing
   * a link to reset his password
   */
  const forgotPassword = React.useCallback(
    async ({ email, onSuccess = () => {}, onError = () => {} }: ForgotPasswordParams) => {
      try {
        await Auth.forgotPassword(email);

        onSuccess();
      } catch (err) {
        onError(err as AuthError);
      }
    },
    []
  );

  /**
   * During mount time only, after having - possibly - set up the Auth configuration, attempt to
   * boot up the user from a previous session
   */
  React.useEffect(() => {
    if (previousUserSessionExists) {
      Auth.currentAuthenticatedUser()
        .then(setAuthUser)
        .catch(() => signOut());
    }
  }, []);

  /**
   * @public
   * The `isAuthenticated` has an undefined value whenever we haven't yet figured out if the user
   * is or isn't authenticated cause we are on the process of examining his token. It has a boolean
   * value in any other case
   */
  const contextValue = React.useMemo(
    () => ({
      isAuthenticated,
      currentAuthChallengeName: authUser?.challengeName || null,
      userInfo,
      updateUserInfo,

      signIn,
      confirmSignIn,
      signOut,

      setNewPassword,
      changePassword,
      resetPassword,
      forgotPassword,

      requestTotpSecretCode,
      verifyTotpSetup,
    }),
    [isAuthenticated, authUser]
  );

  return <AuthContext.Provider value={contextValue}>{children}</AuthContext.Provider>;
};

export { AuthContext, AuthProvider };
