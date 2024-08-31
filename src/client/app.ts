/**
 * Entrypoint for the NerdLock client JS application.
 * It uses the NerdLock client library to load/render messages.
 */
console.log("Loading NerdLock client...");
import "./NerdClient";
import { SenderType } from "./mls/Enums";
import "./mls/Group";
import {EncodeSender, type Sender} from "./mls/Message";
import Uint32 from "./mls/types/Uint32";
console.log(EncodeSender({sender_type: SenderType.member, leaf_index: Uint32.from(0)} satisfies Sender))
