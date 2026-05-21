# Angular 21 Authentication Boilerplate

**Version:** 0.0.0

## Live Application
[https://angular-21-boilerplate-19yp.onrender.com](https://angular-21-boilerplate-19yp.onrender.com)

## Backend API
[https://typescript-auth-api.onrender.com](https://typescript-auth-api.onrender.com)

## API Documentation
[https://typescript-auth-api.onrender.com/api-docs](https://typescript-auth-api.onrender.com/api-docs)

## Environment Files
- `src/environments/environment.ts` - Development configuration
- `src/environments/environment.prod.ts` - Production configuration

## Setup Instructions

### Development
1. Clone the repository
2. Run `npm install`
3. Run `ng serve` and navigate to `http://localhost:4200`

### Production Build
1. Update `src/environments/environment.prod.ts` with your backend API URL
2. Run `ng build --configuration production`
3. Deploy the `dist/angular-21-boilerplate` folder

## Testing with Fake Backend
//...(environment.production ? [] : [fakeBackendProvider]) //disable backend
 //[fakeBackendProvider]  // Always enable fake backend

## Features
- Email sign up and verification
- JWT authentication with refresh tokens
- Role-based authorization (Admin & User)
- Forgot password and reset password
- Profile management
- Admin dashboard

## Tech Stack
- Angular 21
- Bootstrap 5
- RxJS
- JWT Authentication