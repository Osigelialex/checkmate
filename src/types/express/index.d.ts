export {};
declare global {
  namespace Express {
    export interface Request {
      user?: {
        id: string,
        firstName: string,
        lastName: string,
        email: string,
        emailVerified: boolean,
      }
    }
  }
}
