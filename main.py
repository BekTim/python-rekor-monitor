import argparse
from util import extract_public_key, verify_artifact_signature
from merkle_proof import DefaultHasher, verify_consistency, verify_inclusion, compute_leaf_hash
import json
import requests
import base64
import os

def get_log_entry(log_index, debug=False):
    if log_index < 0:
        raise ValueError("Invalid log index")
    if debug:
        print(f"Fetching log entry {log_index} from Rekor")
    response = requests.get(f"https://rekor.sigstore.dev/api/v1/log/entries?logIndex={log_index}")
    if response.status_code != 200:
        raise Exception(f"Rekor error: {response.status_code}")
    data = response.json()
    if not isinstance(data, dict) or not data:
        raise ValueError(f"Unexpected response from Rekor for log index {log_index}")

    entry = list(data.values())[0]
    if entry.get("logIndex") != log_index:
        raise ValueError(
            f"Rekor returned entry {entry.get('logIndex')}, expected {log_index}"
        )

    return entry

def get_verification_proof(log_index, debug=False):
    entry = get_log_entry(log_index,debug)
    return entry["verification"]["inclusionProof"]

def inclusion(log_index, artifact_filepath, debug=False):
    # TODO::
    if not os.path.isfile(artifact_filepath):
        print("Artifact file not found")
        return
    entry = get_log_entry(log_index,debug)
    body = entry["body"]

    body_temp = entry["body"]

    body = base64.b64decode(body)
    body = json.loads(body)
    signature = base64.b64decode(body["spec"]["signature"]["content"])
    certificate = base64.b64decode(body["spec"]["signature"]["publicKey"]["content"])
    public_key = extract_public_key(certificate)
    result = verify_artifact_signature(signature, public_key, artifact_filepath)
    if not result:
        print("Signature verification failed")
        return
    proof = get_verification_proof(log_index,debug)

    index = proof["logIndex"]
    tree_size = proof["treeSize"]
    hashes = proof["hashes"]
    root_hash = proof["rootHash"]

    leaf_hash = compute_leaf_hash(body_temp)

    verify_inclusion(DefaultHasher, index, tree_size, leaf_hash, hashes, root_hash, debug)
    print("Offline verification successful")
    
def get_latest_checkpoint(debug=False):
    response = requests.get("https://rekor.sigstore.dev/api/v1/log")
    if response.status_code != 200:
            raise Exception(f"Rekor error: {response.status_code}")
    data = response.json()
    if debug:
        with open("checkpoint.json", "w", encoding="utf-8") as checkpoint_file:
            json.dump(data, checkpoint_file, indent=4)
    return data

def consistency(prev_checkpoint, debug=False):
    if not prev_checkpoint:
        print("Previous checkpoint is empty")
        return

    latest = get_latest_checkpoint(debug)

    if prev_checkpoint["treeID"] != latest["treeID"]:
        print("Tree IDs do not match")
        return

    url = f"https://rekor.sigstore.dev/api/v1/log/proof?firstSize={prev_checkpoint['treeSize']}&lastSize={latest['treeSize']}&treeID={latest['treeID']}"
    response = requests.get(url)
    if response.status_code != 200:
        raise Exception(f"Rekor error: {response.status_code}")
    proof = response.json()["hashes"]

    # 5. Check
    verify_consistency(
        DefaultHasher,
        prev_checkpoint["treeSize"],   # size1
        latest["treeSize"],            # size2
        proof,                         # proof
        prev_checkpoint["rootHash"],   # root1
        latest["rootHash"],            # root2
    )
    print("Consistency verification successful")
    
def main():
    debug = False
    parser = argparse.ArgumentParser(description="Rekor Verifier")
    parser.add_argument('-d', '--debug', help='Debug mode',
                        required=False, action='store_true') # Default false
    parser.add_argument('-c', '--checkpoint', help='Obtain latest checkpoint\
                        from Rekor Server public instance',
                        required=False, action='store_true')
    parser.add_argument('--inclusion', help='Verify inclusion of an\
                        entry in the Rekor Transparency Log using log index\
                        and artifact filename.\
                        Usage: --inclusion 126574567',
                        required=False, type=int)
    parser.add_argument('--artifact', help='Artifact filepath for verifying\
                        signature',
                        required=False)
    parser.add_argument('--consistency', help='Verify consistency of a given\
                        checkpoint with the latest checkpoint.',
                        action='store_true')
    parser.add_argument('--tree-id', help='Tree ID for consistency proof',
                        required=False)
    parser.add_argument('--tree-size', help='Tree size for consistency proof',
                        required=False, type=int)
    parser.add_argument('--root-hash', help='Root hash for consistency proof',
                        required=False)
    args = parser.parse_args()
    if args.debug:
        debug = True
        print("enabled debug mode")
    if args.checkpoint:
        # get and print latest checkpoint from server
        # if debug is enabled, store it in a file checkpoint.json
        checkpoint = get_latest_checkpoint(debug)
        print(json.dumps(checkpoint, indent=4))
    if args.inclusion:
        inclusion(args.inclusion, args.artifact, debug)
    if args.consistency:
        if not args.tree_id:
            print("please specify tree id for prev checkpoint")
            return
        if not args.tree_size:
            print("please specify tree size for prev checkpoint")
            return
        if not args.root_hash:
            print("please specify root hash for prev checkpoint")
            return

        prev_checkpoint = {}
        prev_checkpoint["treeID"] = args.tree_id
        prev_checkpoint["treeSize"] = args.tree_size
        prev_checkpoint["rootHash"] = args.root_hash

        consistency(prev_checkpoint, debug)

if __name__ == "__main__":
    main()
