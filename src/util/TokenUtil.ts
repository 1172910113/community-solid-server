import { SolidAccessTokenPayload } from "@solid/access-token-verifier";
import { BadRequestHttpError } from '../util/errors/BadRequestHttpError';

export async function verifyBearerToken(authorization: string): Promise<SolidAccessTokenPayload> {
    try {
        const [header, payload, signature] = authorization.split('.');
        let payload_json = Buffer.from(payload, 'base64').toString();
        let object = JSON.parse(payload_json);
        return {
            webid: object.webid,
            iat: object.iat,
            aud: object.aud,
            iss: object.iss,
            exp: object.exp
        }
    } catch (error: unknown) {
        const message = `Error occurs when verifies BearerToken`;
        throw new BadRequestHttpError(message, { cause: error });
    }
}