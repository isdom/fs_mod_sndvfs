/*
 * FreeSWITCH Modular Media Switching Software Library / Soft-Switch Application
 * Copyright (C) 2005-2014, Anthony Minessale II <anthm@freeswitch.org>
 *
 * Version: MPL 1.1
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is FreeSWITCH Modular Media Switching Software Library / Soft-Switch Application
 *
 * The Initial Developer of the Original Code is
 * Anthony Minessale II <anthm@freeswitch.org>
 * Portions created by the Initial Developer are Copyright (C)
 * the Initial Developer. All Rights Reserved.
 *
 * Contributor(s):
 *
 * Anthony Minessale II <anthm@freeswitch.org>
 *
 *
 * mod_sndmem.c -- Framework Demo Module
 *
 */
#include <switch.h>
#include <sndfile.h>

// for vfs mem
#include <oss_c_sdk/oss_api.h>

SWITCH_MODULE_LOAD_FUNCTION(mod_sndmem_load);
SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_sndmem_shutdown);
SWITCH_MODULE_DEFINITION(mod_sndmem, mod_sndmem_load, mod_sndmem_shutdown, NULL);

typedef bool (*vfs_exist_func_t) (const char *path);

typedef void *(*vfs_open_func_t) (const char *path);
typedef void (*vfs_close_func_t) (void *user_data);

typedef size_t (*vfs_get_file_len_func_t) (void *user_data);
typedef size_t (*vfs_seek_func_t) (size_t offset, int whence, void *user_data);
typedef size_t (*vfs_read_func_t) (void *ptr, size_t count, void *user_data);
typedef size_t (*vfs_write_func_t) (const void *ptr, size_t count, void *user_data);
typedef size_t (*vfs_tell_func_t) (void *user_data);

typedef struct {
    vfs_exist_func_t vfs_exist_func;
    vfs_open_func_t vfs_open_func;
    vfs_close_func_t vfs_close_func;
    vfs_get_file_len_func_t vfs_get_file_len_func;
    vfs_seek_func_t vfs_seek_func;
    vfs_read_func_t vfs_read_func;
    vfs_write_func_t vfs_write_func;
    vfs_tell_func_t vfs_tell_func;
} vfs_func_t;

static struct {
	switch_hash_t *format_hash;
	int debug;
	char *allowed_extensions[100];
	int allowed_extensions_count;
} globals;

struct format_map {
	char *ext;
	char *u_ext;
	uint32_t format;
};

struct snd_file_context {
	SF_INFO sf_info;
	SNDFILE *handle;
    void *vfs_data;
    vfs_func_t *vfs_funcs;
};

typedef struct snd_file_context sndfile_context;

static switch_status_t
sndfile_perform_open(snd_file_context *context, const char *path, int mode, switch_file_handle_t *handle);

static void reverse_channel_count(switch_file_handle_t *handle) {
	/* for recording stereo conferences and stereo calls in audio file formats that support only 1 channel.
	 * "{force_channels=1}" does similar, but here switch_core_open_file() was already called and we 
	 * have the handle and we chane the count before _read_ or _write_ are called (where muxing is done). */
	if (handle->channels > 1) {
		handle->real_channels = handle->channels;
		handle->channels = handle->mm.channels = 1;
	}
}

#define MAX_ARGS 10

// mem://{vfs=,uuid=,bucket=}path
static switch_status_t sndfile_file_open(switch_file_handle_t *handle, const char *path)
{
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "using mod_sndmem -- file: %s\n", path);

	snd_file_context *context;
	int mode = 0;
	const char *ext;
	struct format_map *map = nullptr;
	switch_status_t status = SWITCH_STATUS_SUCCESS;
	char *alt_path = nullptr, *last, *l_dup = nullptr;
	size_t alt_len = 0;
	int rates[4] = { 8000, 16000, 32000, 48000 };
	int i;
	sf_count_t frames = 0;
#ifdef WIN32
	char ps = '/';
#else
	char ps = '/';
#endif
    const char *l_braces = strchr(path, '{');
    const char *r_braces = strchr(path, '}');

    if (!l_braces || !r_braces) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Missing Variables: {vfs=?,uuid=?}\n");
        return SWITCH_STATUS_GENERR;
    }

    char *vars = switch_core_strndup(handle->memory_pool, l_braces + 1, r_braces - l_braces - 1);

    if (globals.debug) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "vars: %s\n", vars);
    }

    char *_uuid = nullptr;
    char *_vfs = nullptr;

    char *argv[MAX_ARGS];
    memset(argv, 0, sizeof(char *) * MAX_ARGS);

    int argc = switch_split(vars, ',', argv);
    if (globals.debug) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "var:%s, args count: %d\n", vars, argc);
    }

    for (auto & idx : argv) {
        if (idx) {
            char *ss[2] = {nullptr, nullptr};
            int cnt = switch_split(idx, '=', ss);
            if (cnt == 2) {
                char *var = ss[0];
                char *val = ss[1];
                if (globals.debug) {
                    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "process arg: %s = %s\n", var, val);
                }
                if (!strcasecmp(var, "uuid")) {
                    _uuid = val;
                    continue;
                }
                if (!strcasecmp(var, "vfs")) {
                    _vfs = val;
                    continue;
                }
            }
        }
    }

    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "uuid: %s, vfs: %s\n", _uuid, _vfs);
    switch_core_session_t *session = switch_core_session_force_locate(_uuid);
    if (!session) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "invalid uuid %s, can't locate session\n",
                          _uuid);
        return SWITCH_STATUS_GENERR;
    }

    switch_channel_t *channel = switch_core_session_get_channel(session);
    auto vfs_funcs = (vfs_func_t*)switch_channel_get_private(channel, _vfs);

    // add rwunlock for BUG: un-released channel, ref: https://blog.csdn.net/xxm524/article/details/125821116
    //  We meet : ... Locked, Waiting on external entities
    switch_core_session_rwunlock(session);

    if (!vfs_funcs) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "invalid vfs: %s, not attach vfs provider\n",
                          _vfs);
        return SWITCH_STATUS_GENERR;
    }

	if ((ext = strrchr(path, '.')) == nullptr) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Invalid Format\n");
		return SWITCH_STATUS_GENERR;
	}
	ext++;

	if (switch_test_flag(handle, SWITCH_FILE_FLAG_READ)) {
		mode += SFM_READ;
	}

	if (switch_test_flag(handle, SWITCH_FILE_FLAG_WRITE)) {
		if (switch_test_flag(handle, SWITCH_FILE_WRITE_APPEND) || switch_test_flag(handle, SWITCH_FILE_WRITE_OVER) || handle->offset_pos) {
			mode += SFM_RDWR;
		} else {
			mode += SFM_WRITE;
		}
	}

	if (!mode) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Invalid Mode!\n");
		return SWITCH_STATUS_GENERR;
	}

	if ((context = (snd_file_context*)switch_core_alloc(handle->memory_pool, sizeof(*context))) == nullptr) {
		return SWITCH_STATUS_MEMERR;
	}

    context->vfs_funcs = vfs_funcs;
	map = static_cast<format_map *>(switch_core_hash_find(globals.format_hash, ext));

	if (mode & SFM_WRITE) {
		context->sf_info.channels = (int)handle->channels;
		context->sf_info.samplerate = (int)handle->samplerate;
		if (handle->samplerate == 8000 || handle->samplerate == 16000 ||
			handle->samplerate == 24000 || handle->samplerate == 32000 || handle->samplerate == 48000 ||
			handle->samplerate == 11025 || handle->samplerate == 22050 || handle->samplerate == 44100) {
			context->sf_info.format |= SF_FORMAT_PCM_16;
		}
	}

	if (map) {
		context->sf_info.format |= (int)map->format;
	}

	if (!strcmp(ext, "raw")) {
		context->sf_info.format = SF_FORMAT_RAW | SF_FORMAT_PCM_16;
		if (mode & SFM_READ) {
			context->sf_info.samplerate = 8000;
			context->sf_info.channels = 1;
		}
	} else if (!strcmp(ext, "r8")) {
		context->sf_info.format = SF_FORMAT_RAW | SF_FORMAT_PCM_16;
		if (mode & SFM_READ) {
			context->sf_info.samplerate = 8000;
			context->sf_info.channels = 1;
		}
	} else if (!strcmp(ext, "r16")) {
		context->sf_info.format = SF_FORMAT_RAW | SF_FORMAT_PCM_16;
		if (mode & SFM_READ) {
			context->sf_info.samplerate = 16000;
			context->sf_info.channels = 1;
		}
	} else if (!strcmp(ext, "r24")) {
		context->sf_info.format = SF_FORMAT_RAW | SF_FORMAT_PCM_24;
		if (mode & SFM_READ) {
			context->sf_info.samplerate = 24000;
			context->sf_info.channels = 1;
		}
	} else if (!strcmp(ext, "r32")) {
		context->sf_info.format = SF_FORMAT_RAW | SF_FORMAT_PCM_32;
		if (mode & SFM_READ) {
			context->sf_info.samplerate = 32000;
			context->sf_info.channels = 1;
		}
	} else if (!strcmp(ext, "gsm")) {
		context->sf_info.format = SF_FORMAT_RAW | SF_FORMAT_GSM610;
		context->sf_info.channels = 1;
		if (mode & SFM_WRITE) {
			reverse_channel_count(handle);
		}
		context->sf_info.samplerate = 8000;
	} else if (!strcmp(ext, "ul") || !strcmp(ext, "ulaw")) {
		context->sf_info.format = SF_FORMAT_RAW | SF_FORMAT_ULAW;
		if (mode & SFM_READ) {
			context->sf_info.samplerate = 8000;
			context->sf_info.channels = 1;
		}
	} else if (!strcmp(ext, "al") || !strcmp(ext, "alaw")) {
		context->sf_info.format = SF_FORMAT_RAW | SF_FORMAT_ALAW;
		if (mode & SFM_READ) {
			context->sf_info.samplerate = 8000;
			context->sf_info.channels = 1;
		}
	} else if (!strcmp(ext, "vox")) {
		context->sf_info.format = SF_FORMAT_RAW | SF_FORMAT_VOX_ADPCM;
		context->sf_info.channels = 1;
		context->sf_info.samplerate = 8000;
		if (mode & SFM_WRITE) {
			reverse_channel_count(handle);
		}
	} else if (!strcmp(ext, "adpcm")) {
		context->sf_info.format = SF_FORMAT_WAV | SF_FORMAT_IMA_ADPCM;
		context->sf_info.channels = 1;
		context->sf_info.samplerate = 8000;
		if (mode & SFM_WRITE) {
			reverse_channel_count(handle);
		}
	} else if (!strcmp(ext, "oga") || !strcmp(ext, "ogg")) {
		context->sf_info.format = SF_FORMAT_OGG | SF_FORMAT_VORBIS;
		if (mode & SFM_READ) {
			context->sf_info.samplerate = (int)handle->samplerate;
		}
	} else if (!strcmp(ext, "wve")) {
		context->sf_info.format = SF_FORMAT_WVE | SF_FORMAT_ALAW;
		context->sf_info.channels = 1;
		context->sf_info.samplerate = 8000;
		if (mode & SFM_WRITE) {
			reverse_channel_count(handle);
		}
	} else if (!strcmp(ext, "htk")) {
		context->sf_info.format = SF_FORMAT_HTK | SF_FORMAT_PCM_16;
		context->sf_info.channels = 1;
		context->sf_info.samplerate = 8000;
		if (mode & SFM_WRITE) {
			reverse_channel_count(handle);
		}
	} else if (!strcmp(ext, "iff")) {
		context->sf_info.format = SF_FORMAT_AIFF | SF_FORMAT_PCM_16;
		context->sf_info.channels = 1;
		context->sf_info.samplerate = 8000;
		if (mode & SFM_WRITE) {
			reverse_channel_count(handle);
		}
	} else if (!strcmp(ext, "xi")) {
		context->sf_info.format = SF_FORMAT_XI | SF_FORMAT_DPCM_16;
		context->sf_info.channels = 1;
		context->sf_info.samplerate = 44100;
		if (mode & SFM_WRITE) {
			reverse_channel_count(handle);
		}
	} else if (!strcmp(ext, "sds")) {
		context->sf_info.format = SF_FORMAT_SDS | SF_FORMAT_PCM_16;
		context->sf_info.channels = 1;
		context->sf_info.samplerate = 8000;
		if (mode & SFM_WRITE) {
			reverse_channel_count(handle);
		}
	}

	if ((mode & SFM_WRITE) && sf_format_check(&context->sf_info) == 0) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Error : file format is invalid (0x%08X).\n", context->sf_info.format);
		return SWITCH_STATUS_GENERR;
	}

#if 0 // TODO: disable add the sample rate to the path feature : isdom 20231019
	alt_len = strlen(path) + 10;
	// switch_zmalloc(alt_path, alt_len);
    alt_path = (char*)calloc(1, alt_len);

	switch_copy_string(alt_path, path, alt_len);

	/* This block attempts to add the sample rate to the path
	   if the sample rate is already present in the path it does nothing
	   and reverts to the original file name.
	 */
	if ((last = strrchr(alt_path, ps))) {
		last++;
#ifdef WIN32
		if (strrchr(last, '\\')) {
			last = strrchr(alt_path, '\\');	/* do not swallow a back slash if they are intermixed under windows */
			last++;
		}
#endif
		l_dup = strdup(last);
		switch_assert(l_dup);
		switch_snprintf(last, alt_len - (last - alt_path), "%d%s%s", handle->samplerate, SWITCH_PATH_SEPARATOR, l_dup);
		if (sndfile_perform_open(context, alt_path, mode, handle) == SWITCH_STATUS_SUCCESS) {
			path = alt_path;
		} else {
			/* Try to find the file at the highest rate possible if we can't find one that matches the exact rate.
			   If we don't find any, we will default back to the original file name.
			 */
			for (i = 3; i >= 0; i--) {
				switch_snprintf(last, alt_len - (last - alt_path), "%d%s%s", rates[i], SWITCH_PATH_SEPARATOR, l_dup);
				if (sndfile_perform_open(context, alt_path, mode, handle) == SWITCH_STATUS_SUCCESS) {
					path = alt_path;
					break;
				}
			}
		}
	}
#endif

	if (!context->handle) {
		if (sndfile_perform_open(context, path, mode, handle) != SWITCH_STATUS_SUCCESS) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "Error Opening File [%s] [%s]\n", path, sf_strerror(context->handle));
			status = SWITCH_STATUS_GENERR;
			goto end;
		}
	}
	if (globals.debug) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG,
                          "Opening File [%s] rate [%dhz] channels: [%d]\n", path, context->sf_info.samplerate, (uint8_t) context->sf_info.channels);
	}
	handle->samples = (unsigned int) context->sf_info.frames;
	handle->samplerate = context->sf_info.samplerate;
	handle->channels = (uint8_t) context->sf_info.channels;
	handle->format = context->sf_info.format;
	handle->sections = context->sf_info.sections;
	handle->seekable = context->sf_info.seekable;
	handle->speed = 0;
	handle->private_info = context;

	if (handle->offset_pos) {
		frames = handle->offset_pos;
		handle->offset_pos = 0;
	}

	if (switch_test_flag(handle, SWITCH_FILE_WRITE_APPEND)) {
		handle->pos = sf_seek(context->handle, frames, SEEK_END);
	} else if (switch_test_flag(handle, SWITCH_FILE_WRITE_OVER)) {
		handle->pos = sf_seek(context->handle, frames, SEEK_SET);
	} else {
		sf_command(context->handle, SFC_FILE_TRUNCATE, &frames, sizeof(frames));
	}

	/*
		http://www.mega-nerd.com/libsndfile/api.html#note2
	 */
	if (switch_test_flag(handle, SWITCH_FILE_DATA_SHORT)) {
		sf_command(context->handle,  SFC_SET_SCALE_FLOAT_INT_READ, nullptr, SF_TRUE);
	}

  end:

	switch_safe_free(alt_path);
	switch_safe_free(l_dup);

	return status;
}

sf_count_t vfs_get_file_len(snd_file_context *context) {
    return (sf_count_t)context->vfs_funcs->vfs_get_file_len_func(context->vfs_data);
}

sf_count_t vfs_seek(sf_count_t offset, int whence, snd_file_context *context) {
    return (sf_count_t)context->vfs_funcs->vfs_seek_func(offset, whence, context->vfs_data);
}

sf_count_t vfs_read(void *ptr, sf_count_t count, snd_file_context *context) {
    return (sf_count_t)context->vfs_funcs->vfs_read_func(ptr, count, context->vfs_data);
}

sf_count_t vfs_write(const void *ptr, sf_count_t count, snd_file_context *context) {
    return (sf_count_t)context->vfs_funcs->vfs_write_func(ptr, count, context->vfs_data);
}

sf_count_t vfs_tell(snd_file_context *context) {
    return (sf_count_t)context->vfs_funcs->vfs_tell_func(context->vfs_data);
}

SF_VIRTUAL_IO sg_sf_virtual = {
        reinterpret_cast<sf_vio_get_filelen>(vfs_get_file_len),
        reinterpret_cast<sf_vio_seek>(vfs_seek),
        reinterpret_cast<sf_vio_read>(vfs_read),
        reinterpret_cast<sf_vio_write>(vfs_write),
        reinterpret_cast<sf_vio_tell>(vfs_tell)
};

static switch_status_t
sndfile_perform_open(snd_file_context *context, const char *path, int mode, switch_file_handle_t *handle) {
	if ((mode == SFM_WRITE) || (mode ==  SFM_RDWR)) {
        /*
         * create in memory, no need check and create file first
		if (switch_file_exists(path, handle->memory_pool) != SWITCH_STATUS_SUCCESS) {
			switch_file_t *newfile;
			unsigned int flags = SWITCH_FOPEN_WRITE | SWITCH_FOPEN_CREATE;
			if ((switch_file_open(&newfile, path, flags, SWITCH_FPROT_OS_DEFAULT, handle->memory_pool) != SWITCH_STATUS_SUCCESS)) {
				return SWITCH_STATUS_FALSE;
			}
			if ((switch_file_close(newfile) != SWITCH_STATUS_SUCCESS)) {
				return SWITCH_STATUS_FALSE;
			}
		}
         */
	}

    // TBD: replace with sf_open_virtual
	// if ((context->handle = sf_open(path, mode, &context->sf_info)) == 0) {
    context->vfs_data = context->vfs_funcs->vfs_open_func(path);
    if (!context->vfs_data) {
        return SWITCH_STATUS_FALSE;
    }

    if ((context->handle = sf_open_virtual(&sg_sf_virtual, mode, &context->sf_info, context)) == nullptr) {
        return SWITCH_STATUS_FALSE;
	}

	return SWITCH_STATUS_SUCCESS;
}

static switch_status_t sndfile_file_truncate(switch_file_handle_t *handle, int64_t offset)
{
	auto *context = (snd_file_context *)handle->private_info;
	sf_command(context->handle, SFC_FILE_TRUNCATE, &offset, sizeof(offset));
	handle->pos = 0;
	return SWITCH_STATUS_SUCCESS;
}

static switch_status_t sndfile_file_close(switch_file_handle_t *handle)
{
	auto *context = (snd_file_context *)handle->private_info;

	if (context) {
		sf_close(context->handle);
        context->vfs_funcs->vfs_close_func(context->vfs_data);
	}

	return SWITCH_STATUS_SUCCESS;
}

static switch_status_t sndfile_file_seek(switch_file_handle_t *handle, unsigned int *cur_sample, int64_t samples, int whence)
{
	auto *context = (snd_file_context *)handle->private_info;
	sf_count_t count;
	switch_status_t r = SWITCH_STATUS_SUCCESS;

	if (!handle->seekable) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "File is not seekable\n");
		return SWITCH_STATUS_NOTIMPL;
	}

	if ((count = sf_seek(context->handle, samples, whence)) == ((sf_count_t) -1)) {
		r = SWITCH_STATUS_BREAK;
		count = sf_seek(context->handle, -1, SEEK_END);
	}

	*cur_sample = (unsigned int) count;
	handle->pos = *cur_sample;

	return r;
}

static switch_status_t sndfile_file_read(switch_file_handle_t *handle, void *data, size_t *len)
{
	size_t in_len = *len;
	auto *context = (snd_file_context *)handle->private_info;

	if (switch_test_flag(handle, SWITCH_FILE_DATA_RAW)) {
		*len = (size_t) sf_read_raw(context->handle, data, (sf_count_t)in_len);
	} else if (switch_test_flag(handle, SWITCH_FILE_DATA_INT)) {
		*len = (size_t) sf_readf_int(context->handle, (int *) data, (sf_count_t)in_len);
	} else if (switch_test_flag(handle, SWITCH_FILE_DATA_SHORT)) {
		*len = (size_t) sf_readf_short(context->handle, (short *) data, (sf_count_t)in_len);
	} else if (switch_test_flag(handle, SWITCH_FILE_DATA_FLOAT)) {
		*len = (size_t) sf_readf_float(context->handle, (float *) data, (sf_count_t)in_len);
	} else if (switch_test_flag(handle, SWITCH_FILE_DATA_DOUBLE)) {
		*len = (size_t) sf_readf_double(context->handle, (double *) data, (sf_count_t)in_len);
	} else {
		*len = (size_t) sf_readf_int(context->handle, (int *) data, (sf_count_t)in_len);
	}

	handle->pos += (int64_t)*len;
	handle->sample_count += *len;

	return *len ? SWITCH_STATUS_SUCCESS : SWITCH_STATUS_FALSE;
}

static switch_status_t sndfile_file_write(switch_file_handle_t *handle, void *data, size_t *len)
{
	size_t in_len = *len;
	auto *context = (snd_file_context *)handle->private_info;

	if (switch_test_flag(handle, SWITCH_FILE_DATA_RAW)) {
		*len = (size_t) sf_write_raw(context->handle, data, (sf_count_t)in_len);
	} else if (switch_test_flag(handle, SWITCH_FILE_DATA_INT)) {
		*len = (size_t) sf_writef_int(context->handle, (int *) data, (sf_count_t)in_len);
	} else if (switch_test_flag(handle, SWITCH_FILE_DATA_SHORT)) {
		*len = (size_t) sf_writef_short(context->handle, (short *) data, (sf_count_t)in_len);
	} else if (switch_test_flag(handle, SWITCH_FILE_DATA_FLOAT)) {
		*len = (size_t) sf_writef_float(context->handle, (float *) data, (sf_count_t)in_len);
	} else if (switch_test_flag(handle, SWITCH_FILE_DATA_DOUBLE)) {
		*len = (size_t) sf_writef_double(context->handle, (double *) data, (sf_count_t)in_len);
	} else {
		*len = (size_t) sf_writef_int(context->handle, (int *) data, (sf_count_t)in_len);
	}

	handle->sample_count += *len;

	return sf_error(context->handle) == SF_ERR_NO_ERROR ? SWITCH_STATUS_SUCCESS : SWITCH_STATUS_FALSE;
}

static switch_status_t sndfile_file_set_string(switch_file_handle_t *handle, switch_audio_col_t col, const char *string)
{
	auto *context = (snd_file_context *)handle->private_info;

	return sf_set_string(context->handle, (int) col, string) ? SWITCH_STATUS_FALSE : SWITCH_STATUS_SUCCESS;
}

static switch_status_t sndfile_file_get_string(switch_file_handle_t *handle, switch_audio_col_t col, const char **string)
{
	auto *context = (snd_file_context *)handle->private_info;
	const char *s;

	if ((s = sf_get_string(context->handle, (int) col))) {
		*string = s;
		return SWITCH_STATUS_SUCCESS;
	}

	return SWITCH_STATUS_FALSE;
}

static switch_bool_t exten_is_allowed(const char *exten) {
	int i;
	if (!globals.allowed_extensions[0]) {
		// defaults to allowing all extensions if param "allowed-extensions" not set in cfg
		return SWITCH_TRUE;
	}
	for (i = 0 ; i < globals.allowed_extensions_count; i++) {
		if (exten && globals.allowed_extensions[i] && !strcasecmp(globals.allowed_extensions[i], exten)) {
			return SWITCH_TRUE;
		}
	}
	return SWITCH_FALSE;
}

/* Registration */

static const char **supported_formats;

void dump_formats(const char *fmt) {
    for (int i = 0; supported_formats[i]; i++) {
        switch_log_printf(SWITCH_CHANNEL_LOG_CLEAN, SWITCH_LOG_NOTICE, fmt, i, supported_formats[i]);
    }
}

static switch_status_t setup_formats(switch_memory_pool_t *pool)
{
	SF_FORMAT_INFO info;
	char buffer[128];
	int format, major_count, subtype_count, m, s;
	int len, x, skip, i;
	const char *extras[] = { "r8", "r16", "r24", "r32", "gsm", "ul", "ulaw", "al", "alaw", "adpcm", "vox", "oga", "ogg", nullptr };
	struct {
		char ext[8];
		char new_ext[8];
	} add_ext[] = {
		{"oga", "ogg"}
	};
	int ex_len = (sizeof(extras) / sizeof(extras[0]));
	int add_ext_len = (sizeof(add_ext) / sizeof(add_ext[0]));

	buffer[0] = 0;

	sf_command(nullptr, SFC_GET_LIB_VERSION, buffer, sizeof(buffer));
	if (strlen(buffer) < 1) {
		switch_log_printf(SWITCH_CHANNEL_LOG_CLEAN, SWITCH_LOG_ERROR, "Line %d: could not retrieve lib version.\n", __LINE__);
		return SWITCH_STATUS_FALSE;
	}

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "\nLibSndFile Version : %s Supported Formats\n", buffer);
	switch_log_printf(SWITCH_CHANNEL_LOG_CLEAN, SWITCH_LOG_INFO, "================================================================================\n");
	sf_command(nullptr, SFC_GET_FORMAT_MAJOR_COUNT, &major_count, sizeof(int));
	sf_command(nullptr, SFC_GET_FORMAT_SUBTYPE_COUNT, &subtype_count, sizeof(int));

	//sf_info.channels = 1;
	len = (int)((major_count + (ex_len + 2) + 1) * sizeof(char *));
	supported_formats = (const char **)switch_core_alloc(pool, len);

	len = 0;
	for (m = 0; m < major_count; m++) {
		skip = 0;
		info.format = m;
		sf_command(nullptr, SFC_GET_FORMAT_MAJOR, &info, sizeof(info));
		if (!exten_is_allowed(info.extension)) {
			continue;
		}
		switch_log_printf(SWITCH_CHANNEL_LOG_CLEAN, SWITCH_LOG_INFO, "%s  (extension \"%s\")\n", info.name, info.extension);
		for (x = 0; x < len; x++) {
			if (supported_formats[x] == info.extension) {
				skip++;
				break;
			}
		}
		if (!skip) {
			char *p;
			struct format_map *map = (struct format_map *)switch_core_alloc(pool, sizeof(*map));
			switch_assert(map);

			map->ext = switch_core_strdup(pool, info.extension);
			map->u_ext = switch_core_strdup(pool, info.extension);
			map->format = info.format;
			if (map->ext) {
				for (p = map->ext; *p; p++) {
					*p = (char) switch_tolower(*p);
				}
				switch_core_hash_insert(globals.format_hash, map->ext, map);
			}
			if (map->u_ext) {
				for (p = map->u_ext; *p; p++) {
					*p = (char) switch_toupper(*p);
				}
				switch_core_hash_insert(globals.format_hash, map->u_ext, map);
			}
            // skip extension for temp isdom
			// supported_formats[len++] = (char *) info.extension;

			for (i=0; i < add_ext_len; i++) {
				if (!strcmp(info.extension, add_ext[i].ext)) {
					/* eg: register ogg too, but only if we have oga */
					struct format_map *map = (struct format_map *)switch_core_alloc(pool, sizeof(*map));
					switch_assert(map);

					map->ext = switch_core_strdup(pool, add_ext[i].new_ext);
					map->u_ext = switch_core_strdup(pool, add_ext[i].new_ext);
					map->format = info.format;
					switch_core_hash_insert(globals.format_hash, map->ext, map);
					for (p = map->u_ext; *p; p++) {
						*p = (char) switch_toupper(*p);
					}
					switch_core_hash_insert(globals.format_hash, map->u_ext, map);

					switch_log_printf(SWITCH_CHANNEL_LOG_CLEAN, SWITCH_LOG_INFO, "%s  (extension \"%s\")\n", info.name, add_ext[i].new_ext);
				}
			}
		}
		format = info.format;

		for (s = 0; s < subtype_count; s++) {
			info.format = s;
			sf_command(nullptr, SFC_GET_FORMAT_SUBTYPE, &info, sizeof(info));
			format = (format & SF_FORMAT_TYPEMASK) | info.format;
			//sf_info.format = format;
			/*
			   if (sf_format_check(&sf_info)) {
			   switch_log_printf(SWITCH_CHANNEL_LOG_CLEAN, SWITCH_LOG_DEBUG, "   %s\n", info.name);
			   }
			 */
		}
	}

    dump_formats("step1: [%d] %s\n");
    switch_log_printf(SWITCH_CHANNEL_LOG_CLEAN, SWITCH_LOG_NOTICE, "step1 len: %d\n", len);

    supported_formats[len++] = "vfs";

    switch_log_printf(SWITCH_CHANNEL_LOG_CLEAN, SWITCH_LOG_NOTICE, "len after mem: %d\n", len);

	for (m = 0; m < ex_len; m++) {
		if (exten_is_allowed(extras[m])) {
            // skip extension for temp isdom
			// supported_formats[len++] = extras[m];
		}
	}

    dump_formats("step2: [%d] %s\n");

	switch_log_printf(SWITCH_CHANNEL_LOG_CLEAN, SWITCH_LOG_NOTICE, "================================================================================\n");

	return SWITCH_STATUS_SUCCESS;
}

#define SND_FILE_DEBUG_SYNTAX "<on|off>"
SWITCH_STANDARD_API(mod_sndmem_debug)
{
		if (zstr(cmd)) {
			stream->write_function(stream, "-USAGE: %s\n", SND_FILE_DEBUG_SYNTAX);
		} else {
			if (!strcasecmp(cmd, "on")) {
				globals.debug = 1;
				stream->write_function(stream, "Sndmem Debug: on\n");
			} else if (!strcasecmp(cmd, "off")) {
				globals.debug = 0;
				stream->write_function(stream, "Sndmem Debug: off\n");
			} else {
				stream->write_function(stream, "-USAGE: %s\n", SND_FILE_DEBUG_SYNTAX);
			}
		}
	return SWITCH_STATUS_SUCCESS;
}

switch_hash_t  *g_full_path_mem_file;
switch_thread_rwlock_t *g_rwlock_f2m;

static switch_status_t vfs_mem_on_channel_init(switch_core_session_t *session);

const static switch_state_handler_table_t vfs_mem_cs_handlers = {
        /*! executed when the state changes to init */
        // switch_state_handler_t on_init;
        vfs_mem_on_channel_init,
        /*! executed when the state changes to routing */
        // switch_state_handler_t on_routing;
        nullptr,
        /*! executed when the state changes to execute */
        // switch_state_handler_t on_execute;
        nullptr,
        /*! executed when the state changes to hangup */
        // switch_state_handler_t on_hangup;
        nullptr,
        /*! executed when the state changes to exchange_media */
        // switch_state_handler_t on_exchange_media;
        nullptr,
        /*! executed when the state changes to soft_execute */
        // switch_state_handler_t on_soft_execute;
        nullptr,
        /*! executed when the state changes to consume_media */
        // switch_state_handler_t on_consume_media;
        nullptr,
        /*! executed when the state changes to hibernate */
        // switch_state_handler_t on_hibernate;
        nullptr,
        /*! executed when the state changes to reset */
        // switch_state_handler_t on_reset;
        nullptr,
        /*! executed when the state changes to park */
        // switch_state_handler_t on_park;
        nullptr,
        /*! executed when the state changes to reporting */
        // switch_state_handler_t on_reporting;
        nullptr,
        /*! executed when the state changes to destroy */
        // switch_state_handler_t on_destroy;
        nullptr,
        // int flags;
        0
};

#define FREE_VFS_MEM_FILE_SYNTAX "fullpath=<path>"
SWITCH_STANDARD_API(free_vfs_mem_file_function);

SWITCH_MODULE_LOAD_FUNCTION(mod_sndmem_load) {
	switch_file_interface_t *file_interface;
	switch_api_interface_t *commands_api_interface;
	const char *cf = "sndfile.conf";
	switch_xml_t cfg, xml, settings, param;

	memset(&globals, 0, sizeof(globals));

	switch_core_hash_init(&globals.format_hash);

	if ((xml = switch_xml_open_cfg(cf, &cfg, nullptr))) {
		if ((settings = switch_xml_child(cfg, "settings"))) {
			for (param = switch_xml_child(settings, "param"); param; param = param->next) {
				char *var = (char *) switch_xml_attr_soft(param, "name");
				char *val = (char *) switch_xml_attr_soft(param, "value");
				if (!strcasecmp(var, "allowed-extensions") && val) {
					globals.allowed_extensions_count = (int)switch_separate_string(val, ',', globals.allowed_extensions, (sizeof(globals.allowed_extensions) / sizeof(globals.allowed_extensions[0])));
				}
			}
		}
		switch_xml_free(xml);
	}

	if (setup_formats(pool) != SWITCH_STATUS_SUCCESS) {
		return SWITCH_STATUS_FALSE;
	}

    dump_formats("step3: [%d] %s\n");

    /* connect my internal structure to the blank pointer passed to me */
	*module_interface = switch_loadable_module_create_module_interface(pool, modname);
	file_interface = static_cast<switch_file_interface_t *>(switch_loadable_module_create_interface(*module_interface,
                                                                                                    SWITCH_FILE_INTERFACE));
	file_interface->interface_name = modname;
	file_interface->extens = (char **)supported_formats;
	file_interface->file_open = sndfile_file_open;
	file_interface->file_close = sndfile_file_close;
	file_interface->file_truncate = sndfile_file_truncate;
	file_interface->file_read = sndfile_file_read;
	file_interface->file_write = sndfile_file_write;
	file_interface->file_seek = sndfile_file_seek;
	file_interface->file_set_string = sndfile_file_set_string;
	file_interface->file_get_string = sndfile_file_get_string;

	SWITCH_ADD_API(commands_api_interface, "sndmem_debug", "Set sndmem debug", mod_sndmem_debug, SND_FILE_DEBUG_SYNTAX);

	switch_console_set_complete("add sndmem_debug on");
	switch_console_set_complete("add sndmem_debug off");

    // register vfs_mem state handlers
    switch_core_add_state_handler(&vfs_mem_cs_handlers);

    switch_core_hash_init(&g_full_path_mem_file);
    switch_thread_rwlock_create(&g_rwlock_f2m, pool);

    SWITCH_ADD_API(commands_api_interface, "free_vfs_mem_file", "free vfs mem file", free_vfs_mem_file_function, FREE_VFS_MEM_FILE_SYNTAX);

    /* indicate that the module should continue to be loaded */
	return SWITCH_STATUS_SUCCESS;
}

SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_sndmem_shutdown) {
    switch_thread_rwlock_destroy(g_rwlock_f2m);
    switch_core_hash_destroy(&g_full_path_mem_file);

    // unregister vfs_mem state handlers
    switch_core_remove_state_handler(&vfs_mem_cs_handlers);

	switch_core_hash_destroy(&globals.format_hash);

	return SWITCH_STATUS_SUCCESS;
}

// ============================================= vfs in memory =============================================

typedef struct {
    // TBD: 'vars' need free for strndup
    char *vars;
    // TBD: 'object' need free for strdup
    char *full_path;
    aos_pool_t *aos_pool;
    aos_list_t buffer;
    size_t length;
    size_t position;
    aos_buf_t *cur_buf;
    size_t cur_buf_pos;
} vfs_mem_context_t;

void release_mem_ctx(vfs_mem_context_t *mem_ctx) {
    if (globals.debug) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "release_mem_ctx begin for [%p]\n", mem_ctx);
    }

    if (mem_ctx) {
        aos_pool_destroy(mem_ctx->aos_pool);
        free(mem_ctx->vars);
        free(mem_ctx->full_path);
        free(mem_ctx);
    }
    if (globals.debug) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "release_mem_ctx end for [%p]\n", mem_ctx);
    }
}

#define MAX_API_ARGC 10

// free_vfs_mem_file fullpath=<path>
SWITCH_STANDARD_API(free_vfs_mem_file_function) {
    if (zstr(cmd)) {
        stream->write_function(stream, "free_vfs_mem_file: parameter missing.\n");
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "free_vfs_mem_file: parameter missing.\n");
        return SWITCH_STATUS_SUCCESS;
    }

    switch_status_t status = SWITCH_STATUS_SUCCESS;
    char *_full_path = nullptr;

    switch_memory_pool_t *pool;
    switch_core_new_memory_pool(&pool);
    char *my_cmd = switch_core_strdup(pool, cmd);

    char *argv[MAX_API_ARGC];
    memset(argv, 0, sizeof(char *) * MAX_API_ARGC);

    int argc = switch_split(my_cmd, ' ', argv);
    if (globals.debug) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "cmd:%s, args count: %d\n", my_cmd, argc);
    }

    if (argc < 1) {
        stream->write_function(stream, "fullpath is required.\n");
        switch_goto_status(SWITCH_STATUS_SUCCESS, end);
    }

    for (auto & idx : argv) {
        if (idx) {
            char *ss[2] = {nullptr, nullptr};
            int cnt = switch_split(idx, '=', ss);
            if (cnt == 2) {
                char *var = ss[0];
                char *val = ss[1];
                if (globals.debug) {
                    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "process arg: %s = %s\n", var, val);
                }
                if (!strcasecmp(var, "fullpath")) {
                    _full_path = val;
                    continue;
                }
            }
        }
    }

    if (!_full_path) {
        stream->write_function(stream, "fullpath is required.\n");
        switch_goto_status(SWITCH_STATUS_SUCCESS, end);
    }

    {
        if (globals.debug) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "before wlock g_rwlock_f2m [%p]\n", g_rwlock_f2m);
        }
        switch_thread_rwlock_wrlock( g_rwlock_f2m);
        auto to_free = (vfs_mem_context_t *) switch_core_hash_find(g_full_path_mem_file, _full_path);
        if (to_free) {
            auto deleted = switch_core_hash_delete(g_full_path_mem_file, _full_path);
            // has free inside switch_core_hash_delete by hashtable_destructor_t(to_free)
            // release_mem_ctx(to_free);
            switch_thread_rwlock_unlock (g_rwlock_f2m);
            if (globals.debug) {
                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "after unlock g_rwlock_f2m [%p]\n",
                                  g_rwlock_f2m);
                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE,
                                  "release vfs mem file [%p] associate with %s, check deleted [%p]\n",
                                  to_free, _full_path, deleted);
            }
            stream->write_function(stream, "free_vfs_mem_file: free mem file [%s] success.\n", _full_path);
        } else {
            switch_thread_rwlock_unlock (g_rwlock_f2m);
            if (globals.debug) {
                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "after unlock g_rwlock_f2m [%p]\n",
                                  g_rwlock_f2m);
                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING,
                                  "can't found vfs mem file associate with %s\n", _full_path);
            }
            stream->write_function(stream, "free_vfs_mem_file: free mem file [%s] failed.\n", _full_path);
        }
    }

end:
    switch_core_destroy_memory_pool(&pool);
    return status;
}

size_t mem_seek_func(size_t offset, int whence, vfs_mem_context_t *mem_ctx);

bool is_position_valid(const vfs_mem_context_t *mem_ctx, size_t seek_from_start) {
    return seek_from_start >= 0 && seek_from_start <= mem_ctx->length;
}

bool mem_exist_func(const char *path) {
    const char *l_braces = strchr(path, '{');
    const char *r_braces = strchr(path, '}');
    if (!l_braces || !r_braces) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Missing Variables: {?=?}\n");
        return false;
    }
    char *full_path = strdup(r_braces + 1);

    if (globals.debug) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "before rlock g_rwlock_f2m [%p]\n", g_rwlock_f2m);
    }
    switch_thread_rwlock_rdlock( g_rwlock_f2m);

    auto org = (vfs_mem_context_t*)switch_core_hash_find(g_full_path_mem_file, full_path);

    switch_thread_rwlock_unlock (g_rwlock_f2m);
    if (globals.debug) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "after unlock g_rwlock_f2m [%p]\n", g_rwlock_f2m);
    }

    free(full_path);
    return org != nullptr;
}

void *mem_open_func(const char *path) {
    const char *l_braces = strchr(path, '{');
    const char *r_braces = strchr(path, '}');
    if (!l_braces || !r_braces) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Missing Variables: {?=?}\n");
        return nullptr;
    }
    char *vars = strndup(l_braces + 1, r_braces - l_braces - 1);
    char *full_path = strdup(r_braces + 1);

    if (globals.debug) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "vars: %s, fullpath: %s\n", vars, full_path);
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "before rlock g_rwlock_f2m [%p]\n", g_rwlock_f2m);
    }
    switch_thread_rwlock_rdlock( g_rwlock_f2m);

    auto org = (vfs_mem_context_t*)switch_core_hash_find(g_full_path_mem_file, full_path);

    switch_thread_rwlock_unlock (g_rwlock_f2m);
    if (globals.debug) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "after unlock g_rwlock_f2m [%p]\n", g_rwlock_f2m);
    }
    if (org) {

        if (globals.debug) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "memfile (%s) exist as [%p].\n",
                              full_path, org);
        }
        free(vars);
        free(full_path);

        mem_seek_func(0, SEEK_SET, org);
        if (globals.debug) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "mem_open_func -> full path: %s exist\n",
                              org->full_path);
        }

        return org;
    } else {
        if (globals.debug) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "memfile (%s) !NOT! exist, create new one.\n",
                              full_path);
        }
        auto mem_ctx = (vfs_mem_context_t*)malloc(sizeof(vfs_mem_context_t));
        memset(mem_ctx, 0, sizeof(vfs_mem_context_t));

        // TBD: vars & path need free
        mem_ctx->vars = vars;
        mem_ctx->full_path = full_path;

        // 重新创建一个内存池，第二个参数是NULL，表示没有继承其它内存池。
        aos_pool_create(&mem_ctx->aos_pool, nullptr);
        aos_list_init(&mem_ctx->buffer);

        if (globals.debug) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "before wlock g_rwlock_f2m [%p]\n", g_rwlock_f2m);
        }
        switch_thread_rwlock_wrlock( g_rwlock_f2m);

        if ( SWITCH_STATUS_SUCCESS == switch_core_hash_insert_destructor(g_full_path_mem_file, full_path, mem_ctx,
                                                                         reinterpret_cast<hashtable_destructor_t>(release_mem_ctx))) {
            if (globals.debug) {
                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "memfile %s create success: [%p]\n", full_path,
                                  mem_ctx);
            }
        } else {
            if (globals.debug) {
                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "memfile %s create failed\n", full_path);
            }
        }

        switch_thread_rwlock_unlock (g_rwlock_f2m);
        if (globals.debug) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "after unlock g_rwlock_f2m [%p]\n", g_rwlock_f2m);
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "mem_open_func -> full path: %s\n",
                              mem_ctx->full_path);
        }

        return mem_ctx;
    }
}

void mem_close_func(vfs_mem_context_t *mem_ctx) {
    if (globals.debug) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CONSOLE, "mem_close_func: %s\n", mem_ctx->full_path);
    }
}

size_t mem_get_file_len_func(vfs_mem_context_t *mem_ctx) {
    if (globals.debug) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CONSOLE, "mem_get_file_len_func: %s -> %zu\n", mem_ctx->full_path,
                          mem_ctx->length);
    }
    return mem_ctx->length;
}

size_t mem_seek_func(size_t offset, int whence, vfs_mem_context_t *mem_ctx) {
    if (globals.debug) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CONSOLE, "mem_seek_func: %s -> current pos: %zu, whence:%d:%zu\n",
                          mem_ctx->full_path, mem_ctx->position, whence, offset);
    }
    size_t seek_from_start;
    switch(whence) {
        case SEEK_SET:
            seek_from_start = offset;
            break;
        case SEEK_CUR:
            seek_from_start = mem_ctx->position + offset;
            break;
        case SEEK_END:
            seek_from_start = mem_ctx->length + offset;
            break;
        default:
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "mem_seek_func: invalid whence: %d\n", whence);
            return mem_ctx->position;
    }
    if (!is_position_valid(mem_ctx, seek_from_start)) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "mem_seek_func: invalid offset: %zu while memfile len is: %zu. adjust current position value and !NOT! sync real buf pos\n",
                          seek_from_start, mem_ctx->length);
        mem_ctx->position = seek_from_start;
        return mem_ctx->position;
    }

    mem_ctx->position = seek_from_start;

    aos_buf_t *b;
    int64_t pos = 0;
    aos_list_for_each_entry(aos_buf_t, b, &mem_ctx->buffer, node) {
        int len = aos_buf_size(b);
        if (pos + len >= seek_from_start) {
            mem_ctx->cur_buf = b;
            mem_ctx->cur_buf_pos = seek_from_start - pos;
            break;
        } else {
            pos += len;
        }
    }
    return mem_ctx->position;
}

size_t mem_read_func(void *ptr, size_t count, vfs_mem_context_t *mem_ctx) {
    if (globals.debug) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CONSOLE, "mem_read_func: %s -> current pos: %zu, read size: %ld\n", mem_ctx->full_path,
                          mem_ctx->position, count);
    }
    if (!is_position_valid(mem_ctx, mem_ctx->position)) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "mem_read_func: invalid offset: %zu while memfile len is: %zu. !NOT! read any bytes\n",
                          mem_ctx->position, mem_ctx->length);
        return 0;
    }

    size_t read_size;
    size_t bytes = 0;

    while (true) {
        read_size = mem_ctx->cur_buf ? aos_buf_size(mem_ctx->cur_buf) - mem_ctx->cur_buf_pos : 0;
        if (read_size == 0 && count > bytes) {
            if (mem_ctx->position >= mem_ctx->length) {
                return bytes;
            } else {
                mem_ctx->cur_buf = aos_list_entry(mem_ctx->cur_buf->node.next, aos_buf_t, node);
                mem_ctx->cur_buf_pos = 0;
                continue;
            }
        }
        read_size = aos_min(count - bytes, read_size);
        if (read_size == 0) {
            return bytes;
        }
        memcpy((uint8_t*)ptr + bytes, mem_ctx->cur_buf->start + mem_ctx->cur_buf_pos, read_size);
        bytes += read_size;
        mem_ctx->cur_buf_pos += read_size;
        mem_ctx->position += read_size;
    }
}

void add_new_buf(const void *ptr, size_t count, vfs_mem_context_t *mem_ctx) {
    aos_buf_t *part = aos_create_buf(mem_ctx->aos_pool, (int)count);
    memcpy(part->pos, ptr, count);
    part->last += count;
    aos_list_add_tail(&part->node, &mem_ctx->buffer);
    mem_ctx->length += count;
    mem_ctx->position = mem_ctx->length;
    mem_ctx->cur_buf = part;
    mem_ctx->cur_buf_pos = count;
}

size_t mem_write_func(const void *ptr, size_t count, vfs_mem_context_t *mem_ctx) {
    if (globals.debug) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CONSOLE, "mem_write_func: %s -> current pos: %zu, write size: %ld\n", mem_ctx->full_path,
                          mem_ctx->position, count);
    }
    if (!is_position_valid(mem_ctx, mem_ctx->position)) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "mem_write_func: invalid offset: %zu while memfile len is: %zu. !NOT! write any bytes\n",
                          mem_ctx->position, mem_ctx->length);
        return 0;
    }

    size_t write_size;
    size_t bytes = 0;

    while (true) {
        write_size = mem_ctx->cur_buf ? aos_buf_size(mem_ctx->cur_buf) - mem_ctx->cur_buf_pos : 0;
        if (write_size == 0 && count > bytes) {
            // if (&oss_ctx->cur_buf->node == &oss_ctx->buffer) {
            if (mem_ctx->position >= mem_ctx->length) {
                add_new_buf((uint8_t*)ptr + bytes, count - bytes, mem_ctx);
                bytes = count;
                return bytes;
            } else {
                mem_ctx->cur_buf = aos_list_entry(mem_ctx->cur_buf->node.next, aos_buf_t, node);
                mem_ctx->cur_buf_pos = 0;
                continue;
            }
        }
        write_size = aos_min(count - bytes, write_size);
        if (write_size == 0) {
            return bytes;
        }
        memcpy(mem_ctx->cur_buf->start + mem_ctx->cur_buf_pos, (uint8_t*)ptr + bytes, write_size);
        bytes += write_size;
        mem_ctx->cur_buf_pos += write_size;
        mem_ctx->position += write_size;
    }
}

size_t mem_tell_func(vfs_mem_context_t *mem_ctx) {
    if (globals.debug) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CONSOLE, "mem_tell_func: %s -> current pos: %zu while memfile len is: %zu\n", mem_ctx->full_path,
                          mem_ctx->position, mem_ctx->length);
    }
    return mem_ctx->position;
}

static const vfs_func_t g_vfs_mem_funcs = {
        mem_exist_func,
        mem_open_func,
        reinterpret_cast<vfs_close_func_t>(mem_close_func),
        reinterpret_cast<vfs_get_file_len_func_t>(mem_get_file_len_func),
        reinterpret_cast<vfs_seek_func_t>(mem_seek_func),
        reinterpret_cast<vfs_read_func_t>(mem_read_func),
        reinterpret_cast<vfs_write_func_t>(mem_write_func),
        reinterpret_cast<vfs_tell_func_t>(mem_tell_func)
};

static switch_status_t vfs_mem_on_channel_init(switch_core_session_t *session) {
    switch_channel_t *channel = switch_core_session_get_channel(session);
    switch_channel_set_private(channel, "vfs_mem", &g_vfs_mem_funcs);
    return SWITCH_STATUS_SUCCESS;
}

/* For Emacs:
 * Local Variables:
 * mode:c
 * indent-tabs-mode:t
 * tab-width:4
 * c-basic-offset:4
 * End:
 * For VIM:
 * vim:set softtabstop=4 shiftwidth=4 tabstop=4 noet:
 */
