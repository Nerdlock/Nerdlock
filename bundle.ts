const externalImports = ["@hpke/core", "@hpke/chacha20poly1305", "@hpke/dhkem-x25519", "@hpke/dhkem-x448"];

// bundle NerdClient
Bun.build({
    entrypoints: ["src/client/nerdclient/NerdClient.ts"],
    outdir: "build/client",
    minify: true,
    splitting: true,
    sourcemap: "linked",
    external: externalImports,
    target: "bun"
}).then(output => {
    if (output.success) {
        console.log("Successfully built client application.");
        console.log(`Number of artifacts: ${output.outputs.length}`);
    } else {
        console.error(output.logs);
        throw new Error("Failed to build client application.");
    }
})

// bundle DS
Bun.build({
    entrypoints: ["src/ds/index.ts"],
    outdir: "build/ds",
    minify: true,
    splitting: true,
    sourcemap: "linked",
    external: externalImports,
    target: "bun"
}).then(output => {
    if (output.success) {
        console.log("Successfully built delivery service.");
        console.log(`Number of artifacts: ${output.outputs.length}`);
    } else {
        console.error(output.logs);
        throw new Error("Failed to build delivery service.");
    }
})