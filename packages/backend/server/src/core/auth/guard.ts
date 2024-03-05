import type {
  CanActivate,
  ExecutionContext,
  OnModuleInit,
} from '@nestjs/common';
import {
  Injectable,
  SetMetadata,
  UnauthorizedException,
  UseGuards,
} from '@nestjs/common';
import { ModuleRef, Reflector } from '@nestjs/core';

import { Config, getRequestResponseFromContext } from '../../fundamentals';
import { AuthService, parseAuthUserSeqNum } from './service';

function extractTokenFromHeader(authorization: string) {
  if (!/^Bearer\s/i.test(authorization)) {
    return null;
  }

  return authorization.substring(7);
}

@Injectable()
export class AuthGuard implements CanActivate, OnModuleInit {
  private auth!: AuthService;

  constructor(
    private readonly config: Config,
    private readonly ref: ModuleRef,
    private readonly reflector: Reflector
  ) {}

  onModuleInit() {
    this.auth = this.ref.get(AuthService, { strict: false });
  }

  async canActivate(context: ExecutionContext) {
    const { req } = getRequestResponseFromContext(context);
    const token = req.headers.authorization;

    // check cookie
    let sessionToken: string | undefined =
      req.cookies[this.auth.sessionCookieName];

    // backward compatibility for client older then 0.12
    // TODO: remove
    if (!sessionToken) {
      sessionToken =
        req.cookies[
          this.config.https
            ? '__Secure-next-auth.session-token'
            : 'next-auth.session-token'
        ];
    }

    if (sessionToken) {
      const user = await this.auth.getUser(
        sessionToken,
        parseAuthUserSeqNum(req.headers[this.auth.authUserSeqCookieName])
      );

      if (user) {
        req.user = user;
      }
    }

    // check authorization token
    else if (token) {
      const accessToken = extractTokenFromHeader(token);
      if (accessToken) {
        const user = await this.auth.getUser(accessToken);
        if (user) {
          req.user = user;
        }
      }
    }

    // api is public
    const isPublic = this.reflector.get<boolean>(
      'isPublic',
      context.getHandler()
    );

    if (isPublic) {
      return true;
    }

    if (!req.user) {
      throw new UnauthorizedException('You are not signed in.');
    }

    return true;
  }
}

/**
 * This guard is used to protect routes/queries/mutations that require a user to be logged in.
 *
 * The `@CurrentUser()` parameter decorator used in a `Auth` guarded queries would always give us the user because the `Auth` guard will
 * fast throw if user is not logged in.
 *
 * @example
 *
 * ```typescript
 * \@Auth()
 * \@Query(() => UserType)
 * user(@CurrentUser() user: CurrentUser) {
 *   return user;
 * }
 * ```
 */
export const Auth = () => {
  return UseGuards(AuthGuard);
};

// api is public accessible
export const Public = () => SetMetadata('isPublic', true);
