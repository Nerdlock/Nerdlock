Bun.build({
    entrypoints: ["src/client/app.ts", "src/client/NerdClient.ts"],
    outdir: "build/client",
    minify: true,
    splitting: true,
    sourcemap: "linked",
    external: ["@hpke/core","@hpke/chacha20poly1305","@hpke/dhkem-x25519","@hpke/dhkem-x448"],
}).then(output => {
    if (output.success) {
        console.log("Successfully built client application.");
        console.log(`Number of artifacts: ${output.outputs.length}`);
    } else {
        console.error("Failed to build client application.");
        console.error(output.logs);
    }
})