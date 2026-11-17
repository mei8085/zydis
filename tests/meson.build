pymod = import('python')
py_exe = pymod.find_installation('python3', required: tests)

tests_req = py_exe.found()

if decoder.enabled() and minimal.disabled()
  zydisdecoderstate_exe = executable(
    'ZydisTestDecoderState',
    files('decoder_state.c'),
    dependencies: [zydis_dep],
  )
  test(
    'ZydisDecoderState',
    zydisdecoderstate_exe,
  )
endif

if tests_req
  test(
    'ZydisRegression',
    py_exe,
    args: [
      files('regression.py'),
      'test',
      zydisinfo_exe,
    ],
    workdir: meson.current_source_dir(),
  )

  test(
    'ZydisRegressionEncoder',
    py_exe,
    args: [
      files('regression_encoder.py'),
      zydisfuzzreencoding_exe,
      zydisfuzzencoder_exe,
      zydistestencoderabsolute_exe,
    ],
    workdir: meson.current_source_dir(),
  )
endif

summary(
  {'tests': tests_req},
  section: 'Features',
)
