#include "internal.h"

#include <stdlib.h>
#include <string.h>

#ifdef DNFAST_NATIVE_REAL
#include <modulemd.h>

#define DNFAST_MAX_MODULEMD_BYTES (UINT64_C(128) * UINT64_C(1024) * UINT64_C(1024))

static int append_json_string(GString *output, const char *value) {
    const unsigned char *cursor = (const unsigned char *)value;
    if (value == NULL || !g_utf8_validate(value, -1, NULL)) return 0;
    g_string_append_c(output, '"');
    while (*cursor != '\0') {
        switch (*cursor) {
            case '"': g_string_append(output, "\\\""); break;
            case '\\': g_string_append(output, "\\\\"); break;
            case '\b': g_string_append(output, "\\b"); break;
            case '\f': g_string_append(output, "\\f"); break;
            case '\n': g_string_append(output, "\\n"); break;
            case '\r': g_string_append(output, "\\r"); break;
            case '\t': g_string_append(output, "\\t"); break;
            default:
                if (*cursor < 0x20)
                    g_string_append_printf(output, "\\u%04x", *cursor);
                else
                    g_string_append_c(output, (char)*cursor);
        }
        ++cursor;
    }
    g_string_append_c(output, '"');
    return 1;
}

static int append_strv(GString *output, GStrv values) {
    g_string_append_c(output, '[');
    if (values != NULL) {
        for (size_t index = 0; values[index] != NULL; ++index) {
            if (index != 0) g_string_append_c(output, ',');
            if (!append_json_string(output, values[index])) return 0;
        }
    }
    g_string_append_c(output, ']');
    return 1;
}

static int append_profiles(GString *output, ModulemdModuleStreamV2 *stream) {
    GStrv names = modulemd_module_stream_v2_get_profile_names_as_strv(stream);
    g_string_append(output, ",\"profiles\":[");
    if (names != NULL) {
        for (size_t index = 0; names[index] != NULL; ++index) {
            ModulemdProfile *profile =
                modulemd_module_stream_v2_get_profile(stream, names[index]);
            if (profile == NULL) {
                g_strfreev(names);
                return 0;
            }
            if (index != 0) g_string_append_c(output, ',');
            g_string_append(output, "{\"name\":");
            if (!append_json_string(output, modulemd_profile_get_name(profile))) {
                g_strfreev(names);
                return 0;
            }
            const char *description = modulemd_profile_get_description(profile, "C");
            g_string_append(output, ",\"description\":");
            if (description == NULL)
                g_string_append(output, "null");
            else if (!append_json_string(output, description)) {
                g_strfreev(names);
                return 0;
            }
            GStrv rpms = modulemd_profile_get_rpms_as_strv(profile);
            g_string_append(output, ",\"rpms\":");
            int valid = append_strv(output, rpms);
            g_strfreev(rpms);
            if (!valid) {
                g_strfreev(names);
                return 0;
            }
            g_string_append_c(output, '}');
        }
    }
    g_strfreev(names);
    g_string_append_c(output, ']');
    return 1;
}

static int append_dependencies(GString *output, ModulemdModuleStreamV2 *stream) {
    GPtrArray *alternatives = modulemd_module_stream_v2_get_dependencies(stream);
    g_string_append(output, ",\"dependencies\":[");
    if (alternatives != NULL) {
        for (guint index = 0; index < alternatives->len; ++index) {
            ModulemdDependencies *dependency = g_ptr_array_index(alternatives, index);
            GStrv modules = modulemd_dependencies_get_runtime_modules_as_strv(dependency);
            if (index != 0) g_string_append_c(output, ',');
            g_string_append(output, "{\"requires\":[");
            if (modules != NULL) {
                for (size_t module_index = 0; modules[module_index] != NULL;
                     ++module_index) {
                    if (module_index != 0) g_string_append_c(output, ',');
                    g_string_append(output, "{\"module\":");
                    if (!append_json_string(output, modules[module_index])) {
                        g_strfreev(modules);
                        return 0;
                    }
                    GStrv streams = modulemd_dependencies_get_runtime_streams_as_strv(
                        dependency, modules[module_index]);
                    g_string_append(output, ",\"streams\":");
                    int valid = append_strv(output, streams);
                    g_strfreev(streams);
                    if (!valid) {
                        g_strfreev(modules);
                        return 0;
                    }
                    g_string_append_c(output, '}');
                }
            }
            g_strfreev(modules);
            g_string_append(output, "]}");
        }
    }
    g_string_append_c(output, ']');
    return 1;
}

static int append_stream(GString *output, ModulemdModuleStream *base) {
    if (!MODULEMD_IS_MODULE_STREAM_V2(base)) return 0;
    ModulemdModuleStreamV2 *stream = MODULEMD_MODULE_STREAM_V2(base);
    const char *name = modulemd_module_stream_get_module_name(base);
    const char *stream_name = modulemd_module_stream_get_stream_name(base);
    const char *context = modulemd_module_stream_get_context(base);
    const char *arch = modulemd_module_stream_get_arch(base);
    const char *summary = modulemd_module_stream_v2_get_summary(stream, "C");
    const char *description = modulemd_module_stream_v2_get_description(stream, "C");
    if (name == NULL || stream_name == NULL || context == NULL || arch == NULL)
        return 0;
    g_string_append(output, "{\"name\":");
    if (!append_json_string(output, name)) return 0;
    g_string_append(output, ",\"stream\":");
    if (!append_json_string(output, stream_name)) return 0;
    g_string_append_printf(output, ",\"version\":%" G_GUINT64_FORMAT,
                           modulemd_module_stream_get_version(base));
    g_string_append(output, ",\"context\":");
    if (!append_json_string(output, context)) return 0;
    g_string_append(output, ",\"arch\":");
    if (!append_json_string(output, arch)) return 0;
    g_string_append(output, ",\"summary\":");
    if (summary == NULL) g_string_append(output, "null");
    else if (!append_json_string(output, summary)) return 0;
    g_string_append(output, ",\"description\":");
    if (description == NULL) g_string_append(output, "null");
    else if (!append_json_string(output, description)) return 0;
    if (!append_profiles(output, stream) || !append_dependencies(output, stream))
        return 0;
    GStrv artifacts = modulemd_module_stream_v2_get_rpm_artifacts_as_strv(stream);
    g_string_append(output, ",\"artifacts\":");
    int valid = append_strv(output, artifacts);
    g_strfreev(artifacts);
    if (!valid) return 0;
    g_string_append_c(output, '}');
    return 1;
}

dnfast_status dnfast_modulemd_parse_json(const uint8_t *yaml, size_t yaml_size,
                                         char **json, dnfast_error *error) {
    if (json != NULL) *json = NULL;
    if (yaml == NULL || yaml_size == 0 || json == NULL ||
        yaml_size > DNFAST_MAX_MODULEMD_BYTES ||
        memchr(yaml, '\0', yaml_size) != NULL)
        return dnfast_set_error(error, DNFAST_STATUS_INVALID_ARGUMENT,
                                "modulemd", "parse", "invalid module metadata input");
    char *document = g_strndup((const char *)yaml, yaml_size);
    ModulemdModuleIndex *index = modulemd_module_index_new();
    GPtrArray *failures = NULL;
    GError *detail = NULL;
    if (document == NULL || index == NULL) {
        g_free(document);
        if (index != NULL) g_object_unref(index);
        return dnfast_set_error(error, DNFAST_STATUS_NATIVE_FAILURE,
                                "modulemd", "allocate", "module metadata allocation failed");
    }
    gboolean updated = modulemd_module_index_update_from_string(
        index, document, TRUE, &failures, &detail);
    g_free(document);
    if (!updated || detail != NULL || failures == NULL || failures->len != 0) {
        const char *message = detail == NULL ?
            "module metadata failed strict validation" : detail->message;
        dnfast_status status = dnfast_set_error(
            error, DNFAST_STATUS_INVALID_ARGUMENT, "modulemd", "strict_parse", message);
        if (detail != NULL) g_error_free(detail);
        if (failures != NULL) g_ptr_array_unref(failures);
        g_object_unref(index);
        return status;
    }
    g_ptr_array_unref(failures);
    if (!modulemd_module_index_upgrade_streams(
            index, MD_MODULESTREAM_VERSION_TWO, &detail) ||
        !modulemd_module_index_upgrade_defaults(
            index, MD_DEFAULTS_VERSION_ONE, &detail)) {
        const char *message = detail == NULL ?
            "module metadata version upgrade failed" : detail->message;
        dnfast_status status = dnfast_set_error(
            error, DNFAST_STATUS_INVALID_ARGUMENT, "modulemd", "upgrade", message);
        if (detail != NULL) g_error_free(detail);
        g_object_unref(index);
        return status;
    }
    GString *output = g_string_new("{\"modules\":[");
    GStrv names = modulemd_module_index_get_module_names_as_strv(index);
    int valid = output != NULL && names != NULL;
    for (size_t name_index = 0; valid && names[name_index] != NULL; ++name_index) {
        ModulemdModule *module = modulemd_module_index_get_module(index, names[name_index]);
        GPtrArray *streams = module == NULL ? NULL : modulemd_module_get_all_streams(module);
        if (module == NULL || streams == NULL) {
            valid = 0;
            break;
        }
        if (name_index != 0) g_string_append_c(output, ',');
        g_string_append(output, "{\"name\":");
        valid = append_json_string(output, names[name_index]);
        g_string_append(output, ",\"default_stream\":");
        ModulemdDefaults *defaults = modulemd_module_get_defaults(module);
        const char *default_stream = defaults == NULL ? NULL :
            modulemd_defaults_v1_get_default_stream(MODULEMD_DEFAULTS_V1(defaults), NULL);
        if (default_stream == NULL) g_string_append(output, "null");
        else valid = valid && append_json_string(output, default_stream);
        g_string_append(output, ",\"streams\":[");
        for (guint stream_index = 0; valid && stream_index < streams->len;
             ++stream_index) {
            if (stream_index != 0) g_string_append_c(output, ',');
            valid = append_stream(output, g_ptr_array_index(streams, stream_index));
        }
        g_string_append(output, "]}");
    }
    g_strfreev(names);
    if (valid) g_string_append(output, "]}");
    g_object_unref(index);
    if (!valid) {
        if (output != NULL) g_string_free(output, TRUE);
        return dnfast_set_error(error, DNFAST_STATUS_NATIVE_FAILURE,
                                "modulemd", "catalog", "module metadata catalog is invalid");
    }
    *json = g_string_free(output, FALSE);
    if (*json == NULL)
        return dnfast_set_error(error, DNFAST_STATUS_NATIVE_FAILURE,
                                "modulemd", "catalog", "module catalog allocation failed");
    return DNFAST_STATUS_OK;
}

void dnfast_string_free(char *value) { g_free(value); }

#else

dnfast_status dnfast_modulemd_parse_json(const uint8_t *yaml, size_t yaml_size,
                                         char **json, dnfast_error *error) {
    (void)yaml;
    (void)yaml_size;
    if (json != NULL) *json = NULL;
    return dnfast_set_error(error, DNFAST_STATUS_UNSUPPORTED_ABI,
                            "modulemd", "parse", "real native build disabled");
}

void dnfast_string_free(char *value) { free(value); }

#endif
