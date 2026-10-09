use card_verify_sdk::CardClient;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 5 {
        eprintln!(
            "usage: card-verify-sdk <base-url> <aes-key-base64> <server-public-key-base64> <card-code>"
        );
        std::process::exit(2);
    }
    let builder = CardClient::builder(&args[1], &args[2], &args[3]);
    let client = builder.build()?;
    match client.authenticate(&args[4]) {
        Ok(info) => println!("authenticated, expires_at={:?}", info.expires_at),
        Err(error) => eprintln!("authentication failed: {error}"),
    }
    Ok(())
}
