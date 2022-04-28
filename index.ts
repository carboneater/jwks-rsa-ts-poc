import type { Request } from "express";
import { expressjwt } from "express-jwt";
import type { Jwt, JwtPayload } from "jsonwebtoken";
import JwksRsa from "jwks-rsa";

expressjwt({
    algorithms: ["PS512", "RS256"],
    secret: async (iRequest: Request, token?: Jwt) => {
        if (token) {
            const iss = (token.payload as JwtPayload).iss;
            if (iss) {
                const jwksClient = JwksRsa({
                    cache: true,
                    jwksUri: iss
                })
                return (await jwksClient.getSigningKey(token.header.kid)).getPublicKey()
            } else {
                throw new Error(`Falsey ISS field in provided token`);
            }
        } else {
            throw new Error("Empty token supplied");
        }
    },
})
