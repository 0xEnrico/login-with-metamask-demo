import { recoverPersonalSignature } from 'eth-sig-util';
import { bufferToHex } from 'ethereumjs-util';
import { NextFunction, Request, Response } from 'express';
import jwt from 'jsonwebtoken';

import { config } from '../../config';
import { User } from '../../models/user.model';

import got from 'got';

export const create = async (req: Request, res: Response, next: NextFunction) => {
	const { signature, publicAddress } = req.body;
	if (!signature || !publicAddress) {
		res.status(400).send({
			error: 'Request should have signature and publicAddress',
		});
		return null;
	}

	try {
		const user = await User.findOne({ where: { publicAddress } });
		////////////////////////////////////////////////////
		// Step 1: Get the user with the given publicAddress
		////////////////////////////////////////////////////
		if (!user) {
			res.status(401).send({
				error: `User with publicAddress ${publicAddress} is not found in database`,
			});
			return null;
		}
		////////////////////////////////////////////////////
		// Step 2: Verify digital signature
		////////////////////////////////////////////////////
		const msg = `I am signing my one-time nonce: ${user.nonce}`;
		// We now are in possession of msg, publicAddress and signature. We
		// will use a helper from eth-sig-util to extract the address from the signature
		const msgBufferHex = bufferToHex(Buffer.from(msg, 'utf8'));
		const address = recoverPersonalSignature({
			data: msgBufferHex,
			sig: signature,
		});

		// The signature verification is successful if the address found with
		// sigUtil.recoverPersonalSignature matches the initial publicAddress
		if (address.toLowerCase() !== publicAddress.toLowerCase()) {
			res.status(401).send({
				error: 'Signature verification failed',
			});
			return null;
		}
		////////////////////////////////////////////////////
		// Step 3: Generate a new nonce for the user
		////////////////////////////////////////////////////
		user.nonce = Math.floor(Math.random() * 10000);
		await user.save();

		const tokenAddress = '0x2c172BCE36eF3ebcB283607b3330d656d4A2f6f4';
		const moralisApiKey =
			'7tKXzMbotQrzuXpTU4AtiIPZMHUAm9GZLKuXfwkLEomGZieE1CyoEsIAjMcW6H4V';
		const response = await got.get(`https://deep-index.moralis.io/api/v2/${publicAddress}/nft?chain=mumbai&format=decimal&token_addresses=${tokenAddress}`,
			{
				headers: {
					'X-API-Key': moralisApiKey,
				},
			}
		);
		const resp = JSON.parse(response.body);
		const nfts: any[] = [];
		resp.result.forEach((element: { metadata: any }) => {
			nfts.push(JSON.parse(element.metadata));
		});

		// https://github.com/auth0/node-jsonwebtoken
		const accessToken = jwt.sign(
			{
				payload: {
					id: user.id,
					publicAddress,
				},
			},
			config.secret,
			{
				algorithm: config.algorithms[0],
			}
		);
		return res.send({ accessToken: accessToken, nfts: nfts });
	} catch (err) {
		console.log(err);
		next();
	}
};
