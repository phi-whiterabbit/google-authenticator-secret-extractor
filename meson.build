project('google_authenticator_secrets_extractor', 'cpp', default_options: ['cpp_std=c++17'])

protoc = find_program('protoc', required : true)
protobuf_lite_dep = dependency('protobuf-lite', required : true)

gen = generator(protoc, \
  output    : ['@BASENAME@.pb.cc', '@BASENAME@.pb.h'],
  arguments : ['--proto_path=@CURRENT_SOURCE_DIR@', '--cpp_out=@BUILD_DIR@', '@INPUT@'])

generated = gen.process('google_auth.proto')

cmake   = import('cmake')
cmake_opts = cmake.subproject_options()
cmake_opts.add_cmake_defines({'CMAKE_POSITION_INDEPENDENT_CODE': true})

cmake_opts.add_cmake_defines({'CPPCODEC_BUILD_EXAMPLES': false})
cmake_opts.add_cmake_defines({'CPPCODEC_BUILD_TESTING': false})
cmake_opts.add_cmake_defines({'CPPCODEC_BUILD_TOOLS': false})

cppcodec_proj = cmake.subproject('cppcodec', options: cmake_opts)
cppcodec_dep = cppcodec_proj.get_variable('cppcodec_dep')

cmake_opts.add_cmake_defines({'URIPARSER_SHARED_LIBS': false})
cmake_opts.add_cmake_defines({'URIPARSER_BUILD_DOCS': false})
cmake_opts.add_cmake_defines({'URIPARSER_BUILD_TESTS': false})
cmake_opts.add_cmake_defines({'URIPARSER_BUILD_TOOLS': false})
cmake_opts.add_cmake_defines({'URIPARSER_ENABLE_INSTALL': false})

uriparser_proj = cmake.subproject('uriparser', options: cmake_opts)
uriparser_dep = uriparser_proj.get_variable('uriparser_dep')

lib_google_auth_export_decoder_inc = include_directories('include')

static_lib_google_auth_export_decoder = static_library('google_auth_export_decoder',
  sources : ['google_auth_export_decoder.cpp', generated],
  dependencies: [protobuf_lite_dep, cppcodec_dep, uriparser_dep],
  include_directories : lib_google_auth_export_decoder_inc)

static_lib_google_auth_export_decoder_dep = declare_dependency(include_directories : lib_google_auth_export_decoder_inc,
  link_with : static_lib_google_auth_export_decoder)

executable('google_authenticator_secrets_extractor',
  sources : ['main.cpp'],
  dependencies: [static_lib_google_auth_export_decoder_dep],
  install : true)

