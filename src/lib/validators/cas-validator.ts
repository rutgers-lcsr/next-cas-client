import { CasUser } from '../types';

export interface CasValidationResponse {
    serviceResponse:
        | {
              authenticationFailure: {
                  code: string;
                  description: string;
              };
          }
        | {
              authenticationSuccess: {
                  user: string;
                  proxyGrantingTicket?: string;
                  proxies?: string[];
                  attributes: Record<string, string | string[]>;
              };
          };
}

export const validate = async (validationUrl: string, ticket: string): Promise<CasUser> => {
    try {
        const response = await fetch(`${validationUrl}&ticket=${encodeURIComponent(ticket)}&format=json`);

        if (!response.ok) {
            throw new Error(`CAS validation request failed with status ${response.status}`);
        }
        if (response.headers.get('content-type')?.indexOf('application/json') === -1) {
            throw new Error(
                `CAS validation response is not JSON: 
                ${response.headers.get('content-type')} 
                data: ${await response.text()} 
                validationUrl: ${validationUrl}`,
                {
                    cause: new Error('Invalid content-type in CAS response expected application/json')
                }
            );
        }

        const data = (await response.json()) as CasValidationResponse;

        if ('authenticationFailure' in data.serviceResponse) {
            throw new Error('Ticket failed validation');
        }

        const { user, attributes } = data.serviceResponse.authenticationSuccess;
        return {
            user,
            attributes
        };
    } catch (err) {
        if (err instanceof Error) {
            throw new Error('Ticket failed validation: ' + err.message, { cause: err });
        }
        // if json parsing fails or any other error occurs
        if (err instanceof SyntaxError) {
            throw new Error('Ticket failed validation: Invalid JSON response' + err.message, { cause: err });
        }

        throw new Error('Ticket failed validation');
    }
};
