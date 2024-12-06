import io
import json
import base64
import oci
import logging
import hashlib

from fdk import response

def get_text_secret(secret_ocid):
    signer = oci.auth.signers.get_resource_principals_signer()
    try:
        client = oci.secrets.SecretsClient({}, signer=signer)
        secret_content = client.get_secret_bundle(secret_ocid).data.secret_bundle_content.content.encode('utf-8')
        decrypted_secret_content = base64.b64decode(secret_content).decode("utf-8")
    except Exception as ex:
        print("ERROR: failed to retrieve the secret content", ex, flush=True)
        raise
    return decrypted_secret_content

def get_binary_secret_into_file(secret_ocid, filepath):
    signer = oci.auth.signers.get_resource_principals_signer()
    try:
        client = oci.secrets.SecretsClient({}, signer=signer)
        secret_content = client.get_secret_bundle(secret_ocid).data.secret_bundle_content.content.encode('utf-8')
    except Exception as ex:
        print("ERROR: failed to retrieve the secret content", ex, flush=True)
        raise
    try:
        with open(filepath, 'wb') as secretfile:
            decrypted_secret_content = base64.decodebytes(secret_content)
            secretfile.write(decrypted_secret_content)
    except Exception as ex:
        print("ERROR: cannot write to file " + filepath, ex, flush=True)
        raise
    secret_md5 = hashlib.md5(decrypted_secret_content).hexdigest()
    return decrypted_secret_content, secret_md5

def handler(ctx, data: io.BytesIO=None):
    logging.getLogger().info("function start")

    secret_ocid = secret_type = resp = ""
    try:
        cfg = dict(ctx.Config())
        secret_ocid = cfg["secret_ocid"]
        logging.getLogger().info("Secret ocid = " + secret_ocid)
        secret_type = cfg["secret_type"]
        logging.getLogger().info("Secret type = " + secret_type)
    except Exception as e:
        print('ERROR: Missing configuration keys, secret ocid and secret_type', e, flush=True)
        raise

    if secret_type == "text":
        decrypted_secret_content = get_text_secret(secret_ocid)
        resp = {"message": "Congratulations! You have successfully completed this task of Utilizing OCI Vault Secrets in a Python Function", 
                "secret_content": decrypted_secret_content}
    elif secret_type == "binary":
        decrypted_secret_content, secret_md5 = get_binary_secret_into_file(secret_ocid, "/tmp/secret")
        resp = {"message": "Congratulations! You have successfully completed this task of Utilizing OCI Vault Secrets in a Python Function", 
                "secret_content": decrypted_secret_content, "secret_md5": secret_md5}
    else:
        raise ValueError('the value of the configuration parameter "secret_type" has to be either "text" or "binary"')

    logging.getLogger().info("function end")
    return response.Response(
        ctx, 
        response_data=json.dumps(resp),
        headers={"Content-Type": "application/json"}
    )
