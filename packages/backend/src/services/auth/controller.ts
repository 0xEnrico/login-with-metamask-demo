import { recoverPersonalSignature } from 'eth-sig-util';
import { bufferToHex } from 'ethereumjs-util';
import { NextFunction, Request, Response } from 'express';
import jwt from 'jsonwebtoken';

import { config } from '../../config';
import { User } from '../../models/user.model';

import Web3 from 'web3';

export const create = async (req: Request, res: Response, next: NextFunction) => {
	const { signature, publicAddress } = req.body;
	if (!signature || !publicAddress)
		return res
			.status(400)
			.send({ error: 'Request should have signature and publicAddress' });

	try {
		const user = await User.findOne({ where: { publicAddress } });
		////////////////////////////////////////////////////
		// Step 1: Get the user with the given publicAddress
		////////////////////////////////////////////////////
		if (!user) {
			return res.status(401).send({
				error: `User with publicAddress ${publicAddress} is not found in database`,
			});
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
			return res.status(401).send({
				error: 'Signature verification failed',
			});
		}
		////////////////////////////////////////////////////
		// Step 3: Generate a new nonce for the user
		////////////////////////////////////////////////////
		user.nonce = Math.floor(Math.random() * 10000);
		await user.save();

		const testnet = 'https://matic-mumbai.chainstacklabs.com';

		const web3 = new Web3(new Web3.providers.HttpProvider(testnet));
		const balance = await web3.eth.getBalance(publicAddress);
		console.log(balance);

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
		return res.send(res.json({ accessToken }));
	} catch (err) {
		next();
	}
};
