import Java from "frida-java-bridge";

if (Java.available) {
    let MediaDrm = Java.use("android.media.MediaDrm");
    const certInstances = new Map();

    function bytesToArray(bytes: any) {
        if (bytes === null || bytes === undefined) return null;
        let arr = [];
        for (let i = 0; i < bytes.length; i++) {
            arr.push(bytes[i] & 0xFF);
        }
        return arr;
    }

    function bytesToHex(bytes: any): string {
        if (bytes === null) return "";
        let hex = "";
        for (let i = 0; i < bytes.length; i++) {
            hex += ("0" + (bytes[i] & 0xFF).toString(16)).slice(-2);
        }
        return hex;
    }

    MediaDrm.setPropertyByteArray.implementation = function(propertyName: string, value: any): void {
        //console.log("CALL setPropertyByteArray");

        if (propertyName === "serviceCertificate") {
            //console.log("service cert was set:", bytesToHex(value));
            certInstances.set(this, value);
        }

        this.setPropertyByteArray(propertyName, value);
    };

    MediaDrm.getKeyRequest.implementation = function(scope: any, init: any, mimeType: any, keyType: any, optionalParams: any) {
        //console.log("CALL getKeyRequest", bytesToHex(scope));

        let result = this.getKeyRequest(scope, init, mimeType, keyType, optionalParams);

        send({
            type: "challenge",
            challenge: bytesToArray(result.getData()),
            service_certificate: bytesToArray(certInstances.get(this))
        });

        const op: any = recv('response', function(value: any) {
            if (value.newChallenge) {
                result.mData.value = Java.array('byte', value.newChallenge);
                //console.log("replaced challenge:", result.mData.value);
            }
        });

        op.wait();

        return result;
    };

    MediaDrm.provideKeyResponse.implementation = function(scope: any, response: any) {
        //console.log("CALL provideKeyResponse", bytesToHex(scope));

        send({
            type: "license",
            license: bytesToArray(response)
        });

        return this.provideKeyResponse(scope, response);
    }
} else {
    console.log("No Java VM in this process");
}
