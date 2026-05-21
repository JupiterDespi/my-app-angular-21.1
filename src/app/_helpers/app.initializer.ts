import { catchError, of } from 'rxjs';
import { AccountService } from '@app/_services';

export function appInitializer(accountService: AccountService) {
    return () => accountService.refreshToken()
        .pipe(
            catchError(() => {
                // On error, ensure account is null
                (accountService as any).accountSubject.next(null);
                return of(null);
            })
        );
}