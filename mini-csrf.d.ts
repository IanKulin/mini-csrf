// Express-like types for compatibility without requiring @types/express
interface Request {
  ip?: string;
  headers: { [key: string]: string | string[] | undefined };
  method: string;
  body?: any;
}

interface Response {}

interface NextFunction {
  (err?: any): void;
}

/**
 * Configuration options for CSRF protection
 */
export interface CsrfProtectionOptions {
  /**
   * Server secret used to generate HMAC tokens. Must be at least 32 characters long.
   */
  secret: string;
  
  /**
   * Custom field names for the CSRF token and timestamp
   */
  fieldNames?: {
    /**
     * Name of the hidden form field containing the CSRF token
     * @default "_csrf_token"
     */
    token: string;
    
    /**
     * Name of the hidden form field containing the timestamp
     * @default "_csrf_time"
     */
    time: string;
  };
  
  /**
   * Time-to-live for tokens in milliseconds. Tokens older than this will be rejected.
   * @default 3600000 (1 hour)
   */
  ttl?: number;
}

/**
 * CSRF protection middleware function
 */
export interface CsrfMiddleware {
  (req: Request, res: Response, next: NextFunction): void;
}

/**
 * Function to generate CSRF token HTML for forms
 */
export interface CsrfTokenHtml {
  /**
   * Generates HTML string containing hidden input fields for CSRF token and timestamp
   * @param req - Express request object
   * @returns HTML string with hidden input fields
   */
  (req: Request): string;
}

/**
 * Result object returned by csrfProtection function
 */
export interface CsrfProtectionResult {
  /**
   * Express middleware function that validates CSRF tokens on unsafe HTTP methods
   */
  middleware: CsrfMiddleware;
  
  /**
   * Function to generate CSRF token HTML for forms
   */
  csrfTokenHtml: CsrfTokenHtml;
}

/**
 * CSRF error with specific error code
 */
export interface CsrfError extends Error {
  /**
   * Error code for CSRF validation failures
   */
  code: 'EBADCSRFTOKEN';
}

/**
 * Creates CSRF protection middleware with the given options
 * @param options - Configuration options for CSRF protection
 * @returns Object containing middleware and csrfTokenHtml functions
 * @throws Error if secret is not provided or is less than 32 characters
 * @throws Error if field names are invalid or identical
 */
declare function csrfProtection(options: CsrfProtectionOptions): CsrfProtectionResult;

/**
 * Compares two strings in constant time to prevent timing attacks
 * @param a - First string to compare
 * @param b - Second string to compare
 * @returns True if strings are equal, false otherwise
 */
export declare function constantTimeEquals(a: string, b: string): boolean;

/**
 * Validates that a field name contains only safe characters
 * @param name - Field name to validate
 * @param type - Type of field (used in error messages)
 * @throws Error if field name contains invalid characters
 */
export declare function validateFieldName(name: string, type: string): void;

export default csrfProtection;