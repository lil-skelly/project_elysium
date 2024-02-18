import json
import base64
import binascii

class Packet:
    def __init__(self, unpack_data: bytes = None, **kwargs) -> None:
        self.pack_data = kwargs
        self.unpack_data = unpack_data


    def pack(self) -> str:
        """
        This method is used to pack the data of the object into a JSON formatted string. 

        The method works by iterating over each key-value pair in the `self.data` dictionary. 
        For each pair, it encodes the value using base64 encoding and then decodes it to a string. 
        The result is a new dictionary where the values have been base64 encoded.

        The method finally returns the dictionary as a JSON formatted string.

        Returns:
            A JSON formatted string (type str) representing the base64 encoded values of the `self.data` dictionary.

        Raises:
            TypeError: If the values in the `self.data` dictionary are not encodable in base64.
        """
        payload = {}
        for key, value in self.pack_data.items():
            try:
                payload[key] = base64.b64encode(value).decode()
            except binascii.Error:
                print("[>w<] Error: Could not base64 encode the value. Proceeding without encoding.")
                payload[key] = value

        return json.dumps(payload)

    def unpack(self) -> dict[bytes]:
        """
        This method is used to unpack a JSON formatted string into a dictionary.
        
        The method works by decoding the JSON formatted string into a dictionary.
        Then, it iterates over each key-value pair in the dictionary.
        For each pair, it decodes the base64 encoded value and then encodes it to a bytes object.
        The result is a new dictionary where the values have been base64 decoded.

        Returns:
            A dictionary where the values have been base64 decoded.
        
        Raises:
            TypeError: If the values in the dictionary are not decodable in base64.
        
        """
        payload = json.loads(self.unpack_data)
        for key, value in payload.items():
            try:
                payload[key] = base64.b64decode(value)
            except binascii.Error:
                print("[>w<] Error: Could not base64 decode the value. Proceeding without decoding.")
                payload[key] = value

        return payload

# packet = Packet(enc_session_key=b"session_key", nonce=b"nonce")
# packed_data = packet.pack()
# unpacked_data = Packet(unpack_data=packed_data).unpack()
# print(packed_data)
# print(unpacked_data)