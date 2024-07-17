// Copyright 2024 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.

// Unless required by applicable law or agreed to in writing,
// this software is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR REPRESENTATIONS OF ANY KIND, either express or
// implied. See the LICENSE-MIT and LICENSE-APACHE files for the
// specific language governing permissions and limitations under
// each license.

//! Example App showing how to use the new v2 API
use std::{io::Cursor, time::Instant};

use anyhow::Result;
use c2pa::{Builder, CallbackSigner, SigningAlg};
use serde_json::json;

const CERTS: &[u8] = include_bytes!("../tests/fixtures/certs/ed25519.pub");
const PRIVATE_KEY: &[u8] = include_bytes!("../tests/fixtures/certs/ed25519.pem");

fn manifest_def(title: &str, format: &str) -> String {
    json!({
        "title": title,
        "format": format,
        "claim_generator_info": [
            {
                "name": "c2pa test",
                "version": env!("CARGO_PKG_VERSION")
            }
        ],
        "ingredients": [
            {
                "title": "Test",
                "format": "image/jpeg",
                "instance_id": "12345",
                "relationship": "inputTo"
            }
        ],
        "assertions": [
            {
                "label": "c2pa.actions",
                "data": {
                    "actions": [
                        {
                            "action": "c2pa.edited",
                            "digitalSourceType": "http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia",
                            "softwareAgent": {
                                "name": "My AI Tool",
                                "version": "0.1.0"
                            }
                        }
                    ]
                }
            }
        ]
    }).to_string()
}

// This is a simple test of signing speed
fn main() -> Result<()> {
    let title = "v2_edited.jpg";
    let format = "image/jpeg";

    let json = manifest_def(title, format);

    let ed_signer = |_context: *const (), data: &[u8]| ed_sign(data, PRIVATE_KEY);
    let signer = CallbackSigner::new(ed_signer, SigningAlg::Ed25519, CERTS);

    {
        let mut total_duration = std::time::Duration::new(0, 0);

        let num_runs = 100;
        for _i in 0..num_runs {
            let start_time = Instant::now();
            // sign the ManifestStoreBuilder and write it to the output stream
            let mut source =
                std::fs::File::open("/Users/gpeacock/dev/c2pa-python/tests/fixtures/tapban.jpg")?;
            let mut dest = Cursor::new(Vec::new());

            let mut builder = Builder::from_json(&json)?;
            builder.sign(&signer, format, &mut source, &mut dest)?;
            let end_time = Instant::now();
            let duration = end_time - start_time;
            total_duration += duration;
        }
        let average_duration = total_duration / num_runs as u32;
        println!("Average time per run: {:?}", average_duration);
    }
    Ok(())
}

// Sign the data using the Ed25519 algorithm
fn ed_sign(data: &[u8], private_key: &[u8]) -> c2pa::Result<Vec<u8>> {
    use ed25519_dalek::{Signature, Signer, SigningKey};
    use pem::parse;

    // Parse the PEM data to get the private key
    let pem = parse(private_key).map_err(|e| c2pa::Error::OtherError(Box::new(e)))?;
    // For Ed25519, the key is 32 bytes long, so we skip the first 16 bytes of the PEM data
    let key_bytes = &pem.contents()[16..];
    let signing_key =
        SigningKey::try_from(key_bytes).map_err(|e| c2pa::Error::OtherError(Box::new(e)))?;
    // Sign the data
    let signature: Signature = signing_key.sign(data);

    Ok(signature.to_bytes().to_vec())
}
