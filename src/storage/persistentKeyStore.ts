import { User } from "models/custom/User";

let store:{ [key:string]: User } = {};

export function get(key:string) {
	return store[key];
}

export function set(key:string, value:User) {
	store[key] = value;
}