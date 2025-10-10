import argparse
import logging
import time
from pathlib import Path
from typing import List

import frida
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA1, HMAC, SHA256
from Crypto.Signature import pss
from frida.core import Session
from pywidevine import Device, Cdm, PSSH, Key
from pywidevine.exceptions import SignatureMismatch
from pywidevine.license_protocol_pb2 import SignedMessage, LicenseRequest, LicenseType, License


class AWP:
    def __init__(self, session: Session, script: str, token_only: bool, widevine_device: Device, keys_callback):
        self.session = session
        self.script = self.session.create_script(script)
        self.token_only = token_only

        self.widevine_device = widevine_device
        self.cdm = Cdm.from_device(widevine_device)

        self.keys_callback = keys_callback

        self._logger = logging.getLogger(__name__)
        self._sessions = {}

    @staticmethod
    def extract_optional_parameters(license_request: LicenseRequest) -> dict:
        if not license_request.client_id.ListFields():
            return {}

        optional_params = {}

        for nv in license_request.client_id.client_info:
            if nv.name == "company_name":
                break

            optional_params[nv.name] = nv.value

        return optional_params

    def __hook(self, message: dict, data: bytes) -> None:
        if message["type"] == "error":
            self._logger.error(message["stack"])

        elif message["type"] == "send":
            payload = message["payload"]

            if payload["type"] == "challenge":
                challenge = bytes(payload["challenge"])

                self._logger.info("Received challenge")

                if self.token_only:
                    signed_message = SignedMessage()
                    signed_message.ParseFromString(challenge)

                    license_request = LicenseRequest()
                    license_request.ParseFromString(signed_message.msg)

                    if not license_request.client_id.ListFields():
                        raise Exception("Token only is not supported when a service certificate is being used")

                    # we can do this because the client info is in no way linked to the SignedDrmCertificate
                    license_request.client_id.token = self.widevine_device.client_id.token
                    request_id = license_request.content_id.widevine_pssh_data.request_id

                    new_license_request_msg = license_request.SerializeToString()

                    signed_message.msg = new_license_request_msg
                    signed_message.signature = pss.new(self.widevine_device.private_key).sign(SHA1.new(new_license_request_msg))

                    new_challenge = signed_message.SerializeToString()

                    self._sessions[request_id] = Cdm.derive_context(new_license_request_msg)
                else:
                    initial_signed_message = SignedMessage()
                    initial_signed_message.ParseFromString(challenge)

                    # print(initial_signed_message)

                    initial_license_request = LicenseRequest()
                    initial_license_request.ParseFromString(initial_signed_message.msg)

                    wv_pssh_data = initial_license_request.content_id.widevine_pssh_data
                    pssh = PSSH(wv_pssh_data.pssh_data[0])
                    optional_params = self.extract_optional_parameters(initial_license_request)

                    session_id = self.cdm.open()

                    if payload["service_certificate"]:
                        provider_id = self.cdm.set_service_certificate(session_id, bytes(payload["service_certificate"]))
                        self._logger.info(f"Service certificate has been set: {provider_id}")

                    generated_challenge = self.cdm.get_license_challenge(session_id, pssh, LicenseType.Name(wv_pssh_data.license_type), optional_parameters=optional_params)

                    signed_message = SignedMessage()
                    signed_message.ParseFromString(generated_challenge)
                    signed_message.oemcrypto_core_message = initial_signed_message.oemcrypto_core_message

                    # print(signed_message)

                    license_request = LicenseRequest()
                    license_request.ParseFromString(signed_message.msg)

                    request_id = license_request.content_id.widevine_pssh_data.request_id
                    self._sessions[request_id] = session_id

                    new_challenge = signed_message.SerializeToString()

                self.script.post({
                    "type": "response",
                    "newChallenge": list(new_challenge)
                })

            elif payload["type"] == "license":
                self._logger.info("Received license")

                licence = bytes(payload["license"])

                signed_message = SignedMessage()
                signed_message.ParseFromString(licence)

                license_message = License()
                license_message.ParseFromString(signed_message.msg)

                request_id = license_message.id.request_id

                if self.token_only:
                    context = self._sessions[request_id]

                    enc_key, mac_key_server, _ = Cdm.derive_keys(
                        *context,
                        key=PKCS1_OAEP.new(self.widevine_device.private_key).decrypt(signed_message.session_key)
                    )

                    computed_signature = HMAC. \
                        new(mac_key_server, digestmod=SHA256). \
                        update(signed_message.oemcrypto_core_message or b""). \
                        update(signed_message.msg). \
                        digest()

                    if signed_message.signature != computed_signature:
                        raise SignatureMismatch("Signature Mismatch on License Message, rejecting license")

                    keys = [
                        Key.from_key_container(key, enc_key)
                        for key in license_message.key
                        if key.type == License.KeyContainer.CONTENT
                    ]
                else:
                    session_id = self._sessions[request_id]

                    self.cdm.parse_license(session_id, licence)
                    keys = self.cdm.get_keys(session_id, type_="CONTENT")
                    self.cdm.close(session_id)

                self.keys_callback(keys)

                del self._sessions[request_id]

    def attach(self) -> None:
        self.script.on('message', lambda message, data: self.__hook(message, data))
        self.script.load()

        self._logger.info("Ready. Waiting for events...")

        while True:
            time.sleep(1)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="AWP - Android Widevine Proxy")

    parser.add_argument(
        "app_name",
        metavar="<APP_NAME>",
        type=str,
        help="The name of the app to intercept"
    )

    parser.add_argument(
        "widevine_device",
        metavar="<WVD>",
        type=Path,
        help="Path of the widevine device"
    )

    parser.add_argument(
        "--key-format",
        type=str,
        choices=["default", "mp4decrypt", "shaka-packager"],
        default="default",
        help="Format of printed keys"
    )

    parser.add_argument(
        "--token-only",
        action="store_true",
        help="Only replace the token in the challenge (only if privacy mode is off)"
    )

    logging.basicConfig(level=logging.INFO)

    logger = logging.getLogger(__name__)

    args = parser.parse_args()

    logger.info("Finding USB device...")
    device = frida.get_usb_device()

    logger.info("Hooking app...")
    session = device.attach(args.app_name)

    script_code = open("_agent.js", "r").read()

    def log_keys(keys: List[Key]):
        if args.key_format == "default":
            for key in keys:
                logger.info(f"[{key.type}] {key.kid.hex}:{key.key.hex()}")
        elif args.key_format == "mp4decrypt":
            logger.info(" ".join(f"--key {k.kid.hex}:{k.key.hex()}" for k in keys))
        elif args.key_format == "shaka-packager":
            logger.info(" ".join(f"--keys key_id={k.kid.hex}:key={k.key.hex()}" for k in keys))

    awp = AWP(
        session=session,
        script=script_code,
        widevine_device=Device.load(args.widevine_device),
        token_only=args.token_only,
        keys_callback=log_keys
    )

    awp.attach()
