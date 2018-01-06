var gulp = require('gulp');
var fs = require('fs');
var header = require('gulp-header');
var clean = require('gulp-clean');
var tar = require('gulp-tar');
var gzip = require('gulp-gzip');
var sequence = require('gulp-sequence')
var gitDescribeSync = require('git-describe').gitDescribeSync;

var banner = ['/**',
      ' * Wish - Peer-to-peer identity based network layer',
      ' *',
      ' * Copyright (C) 2018, ControlThings Oy Ab, All Rights Reserved',
      ' *',
      ' * Licensed under the Apache License, Version 2.0 (the "License"); you may',
      ' * not use this file except in compliance with the License.',
      ' * You may obtain a copy of the License at',
      ' *',
      ' * http://www.apache.org/licenses/LICENSE-2.0',
      ' *',
      ' * @license Apache-2.0',
      ' */',
      ''].join('\n');

var info = gitDescribeSync();

var buildDir = '../build/source/';
var name = 'wish-'+ info.raw;
var build = buildDir + name;

gulp.task('wish-all', function () { 
    return gulp.src(['../**/*.*', '!../build', '!../build/**/*.*', '!../tools/node_modules', '!../tools/node_modules/**/*.*', '!../nbproject', '!../nbproject/**/*.*']).pipe(gulp.dest(build)); 
});

gulp.task('wish-src', function () { 
    return gulp.src(['../src/**/*.{c,h}']).pipe(header(banner)).pipe(gulp.dest(build +'/src')); 
});

gulp.task('wish-port', function () { 
    return gulp.src(['../port/**/*.{c,h}']).pipe(header(banner)).pipe(gulp.dest(build +'/port')); 
});

gulp.task('wish-deps', function () {
    return gulp.src(['../deps/**/*.*']).pipe(gulp.dest(build +'/deps'));
});

gulp.task('wish-rpc-src', function () {
    return gulp.src(['../deps/wish-rpc-c99/**/*.{c,h}']).pipe(header(banner)).pipe(gulp.dest(build +'/deps/wish-rpc-c99'));
});

gulp.task('tar-gz', function () {
    
    fs.writeFileSync(build +'/VERSION', info.raw);
    
    return gulp
            .src(buildDir +'**')
            .pipe(tar('wish-source.tar'))
            .pipe(gzip())
            .pipe(gulp.dest('../build'));
});

gulp.task('default', sequence(['clean'], ['wish-all'], ['wish-src'], ['wish-port'], ['wish-deps'], ['wish-rpc-src'], ['tar-gz']));
    
gulp.task('clean', function () {
    return gulp.src('../build/source')
        .pipe(clean({force: true, read: false}));
});

