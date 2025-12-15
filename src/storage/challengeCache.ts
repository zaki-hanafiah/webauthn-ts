let cache: { [key: string]: any } = {}

export function get(key: string) {
    return cache[key]
}

export function set(key: string, value: any) {
    cache[key] = value
}
// __activity_fill_marker__ 2025-12-15 0
