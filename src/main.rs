use clap::{Arg, Command};
use reqwest::header::{ACCEPT, AUTHORIZATION};
use reqwest::Client;
use serde::Deserialize;
use serde_json::Value;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command as ExecCommand;
use tokio;

#[derive(Deserialize, Debug)]
struct ImageManifest {
    // Define the fields of the image manifest here
    v1: i32,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let matches = Command::new("docker-engine-rs")
        .version("0.1")
        .author("Your Name")
        .about("A simple Docker engine in Rust")
        .subcommand(
            Command::new("run")
                .about("Runs a container from the specified image")
                .arg(
                    Arg::new("IMAGE")
                        .required(true)
                        .help("The name of the image to run"),
                ),
        )
        .get_matches();

    if let Some(run_matches) = matches.subcommand_matches("run") {
        if let Some(image_name) = run_matches.get_one::<String>("IMAGE") {
            println!("Running container with image: {}", image_name);
            let token = get_token(image_name).await?;
            let digest = get_arm64_digest(image_name, &token).await?;
            println!("found_arm_digest={}", digest);
            let manifest = get_image_manifest(image_name, &token, &digest).await?;
            let mut path = PathBuf::from("./images");
            path = path.join(image_name.replace(":", "_"));
            let extract_path = path.to_string_lossy().to_string();
            for layer in manifest.layers {
                download_layer(&layer.digest, &token, image_name).await;
                let layer_file = format!("{}.tar", layer.digest.replace(":", "_"));
                extract_layer(&layer_file, &extract_path);
            }
        }
    }
    Ok(())
}

#[derive(Deserialize, Debug)]
struct TokenResponse {
    token: String,
}

async fn get_token(image_name: &str) -> Result<String, Box<dyn std::error::Error>> {
    let client = Client::new();
    let response = client
        .get("https://auth.docker.io/token")
        .query(&[
            ("service", "registry.docker.io"),
            (
                "scope",
                &format!("repository:library/{image_name}:pull").to_string(),
            ),
        ])
        .send()
        .await?;

    let token_response: TokenResponse = response.json().await?;
    println!("token_resp={:?}", token_response);
    Ok(token_response.token)
}

#[derive(Deserialize, Debug, Clone)]
struct Layer {
    mediaType: String,
    size: u64,
    digest: String,
}

#[derive(Deserialize, Debug)]
struct Manifest {
    schemaVersion: i32,
    layers: Vec<Layer>,
}

#[derive(Deserialize, Debug)]
struct ManifestList {
    manifests: Vec<ManifestEntry>,
}

#[derive(Deserialize, Debug)]
struct ManifestEntry {
    digest: String,
    mediaType: String,
    size: i32,
    platform: Platform,
}

#[derive(Deserialize, Debug)]
struct Platform {
    architecture: String,
    os: String,
}

async fn get_arm64_digest(
    image_name: &str,
    token: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let client = Client::new();
    let url = format!(
        "https://registry-1.docker.io/v2/library/{}/manifests/latest",
        image_name
    );

    let response = client
        .get(&url)
        .header(AUTHORIZATION, format!("Bearer {}", token))
        .header(
            ACCEPT,
            "application/vnd.docker.distribution.manifest.list.v2+json",
        )
        .send()
        .await?;

    let manifest_list: ManifestList = response.json().await?;

    // Find the ARM64 manifest
    let arm64_manifest = manifest_list
        .manifests
        .into_iter()
        .find(|m| m.platform.architecture == "arm64")
        .ok_or("ARM64 manifest not found")?;
    Ok(arm64_manifest.digest)
}

async fn get_image_manifest(
    image_name: &str,
    token: &str,
    digest: &str,
) -> Result<Manifest, Box<dyn std::error::Error>> {
    let client = Client::new();
    let url = format!("https://registry-1.docker.io/v2/library/{image_name}/manifests/{digest}");
    println!("url={}", url);

    let response = client
        .get(&url)
        .header(AUTHORIZATION, format!("Bearer {}", token))
        .header(
            ACCEPT,
            "application/vnd.docker.distribution.manifest.v2+json",
        )
        .header(ACCEPT, "application/vnd.oci.image.manifest.v1+json")
        .send()
        .await?;

    if response.status().is_success() {
        let manifest: Manifest = response.json().await?;
        println!("ok_manifest={:?}", manifest);
        Ok(manifest)
    } else {
        Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Failed to get manifest: {:?}", response.status()),
        )))
    }
}

async fn download_layer(
    digest: &str,
    token: &str,
    image_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::new();
    let url = format!(
        "https://registry-1.docker.io/v2/library/{}/blobs/{}",
        image_name, digest
    );

    let response = client
        .get(&url)
        .header(AUTHORIZATION, format!("Bearer {}", token))
        .send()
        .await?;

    if response.status().is_success() {
        let content = response.bytes().await?;

        // Save the content (which is a tarball) to a file
        let filename = format!("{}.tar", digest.replace(":", "_"));
        let mut file = File::create(&filename)?;
        file.write_all(&content)?;

        println!(
            "Downloaded and saved layer: {} ({} bytes)",
            filename,
            content.len()
        );
    } else {
        println!("Failed to download layer: {:?}", response.status());
    }

    Ok(())
}

fn extract_layer(layer_file: &str, extract_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Create the extraction directory if it doesn't exist
    let path = Path::new(extract_path);
    if !path.exists() {
        std::fs::create_dir_all(path)?;
    }

    // Extract the tar file to the specified directory
    let output = ExecCommand::new("tar")
        .arg("-xvf")
        .arg(layer_file)
        .arg("-C")
        .arg(extract_path)
        .output()?;

    if !output.status.success() {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Failed to extract layer: {}", layer_file),
        )));
    }

    println!("Extracted layer: {} to {}", layer_file, extract_path);
    Ok(())
}

fn run_container(rootfs: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Using `chroot` to simulate a container environment (changing the root directory)
    let output = ExecCommand::new("chroot")
        .arg(rootfs) // Root filesystem directory
        .arg("/bin/ls") // Shell to run in the container
        .output()?; // Capture the output

    if output.status.success() {
        println!("Container ran successfully.");
        println!("Output: {}", String::from_utf8_lossy(&output.stdout));
    } else {
        println!("Failed to run container.");
        println!("Error: {}", String::from_utf8_lossy(&output.stderr));
    }

    Ok(())
}
