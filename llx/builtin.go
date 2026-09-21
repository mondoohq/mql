// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package llx

import (
	"errors"
	"fmt"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers-sdk/v1/resources"
	"go.mondoo.com/mql/types"
)

type chunkHandlerV2 struct {
	// FIXME: DEPRECATED, remove in v13.0 or earlier vv
	// The compiler should move entirely to MQLc. Adding this here causes us to do
	// some lookup gymnastics in mqlc and the functionality is very limited because we
	// can't really access the compiler and its context (LLX can't include MQLc,
	// since MQLc relies on LLX). Consolidate the compiler in LLX only.
	Compiler func(types.Type, types.Type) (string, error)
	// ^^
	f     func(*blockExecutor, *RawData, *Chunk, uint64) (*RawData, uint64, error)
	Label string
	Typ   types.Type
}

// BuiltinFunctions for all builtin types
var BuiltinFunctionsV2 map[types.Type]map[string]chunkHandlerV2

func init() {
	BuiltinFunctionsV2 = map[types.Type]map[string]chunkHandlerV2{
		types.Nil: {
			// == / !=
			string("==" + types.Nil):          {f: chunkEqTrueV2, Label: "=="},
			string("!=" + types.Nil):          {f: chunkNeqFalseV2, Label: "!="},
			string("==" + types.Bool):         {f: chunkEqFalseV2, Label: "=="},
			string("!=" + types.Bool):         {f: chunkNeqTrueV2, Label: "!="},
			string("==" + types.Int):          {f: chunkEqFalseV2, Label: "=="},
			string("!=" + types.Int):          {f: chunkNeqTrueV2, Label: "!="},
			string("==" + types.Float):        {f: chunkEqFalseV2, Label: "=="},
			string("!=" + types.Float):        {f: chunkNeqTrueV2, Label: "!="},
			string("==" + types.String):       {f: chunkEqFalseV2, Label: "=="},
			string("!=" + types.String):       {f: chunkNeqTrueV2, Label: "!="},
			string("==" + types.Regex):        {f: chunkEqFalseV2, Label: "=="},
			string("!=" + types.Regex):        {f: chunkNeqTrueV2, Label: "!="},
			string("==" + types.Time):         {f: chunkEqFalseV2, Label: "=="},
			string("!=" + types.Time):         {f: chunkNeqTrueV2, Label: "!="},
			string("==" + types.Dict):         {f: chunkEqFalseV2, Label: "=="},
			string("!=" + types.Dict):         {f: chunkNeqTrueV2, Label: "!="},
			string("==" + types.Empty):        {f: chunkEqTrueV2, Label: "=="},
			string("!=" + types.Empty):        {f: chunkNeqTrueV2, Label: "!="},
			string("==" + types.ArrayLike):    {f: chunkEqFalseV2, Label: "=="},
			string("!=" + types.ArrayLike):    {f: chunkNeqTrueV2, Label: "!="},
			string("==" + types.MapLike):      {f: chunkEqFalseV2, Label: "=="},
			string("!=" + types.MapLike):      {f: chunkNeqTrueV2, Label: "!="},
			string("==" + types.ResourceLike): {f: chunkEqFalseV2, Label: "=="},
			string("!=" + types.ResourceLike): {f: chunkNeqTrueV2, Label: "!="},
			string("==" + types.FunctionLike): {f: chunkEqFalseV2, Label: "=="},
			string("!=" + types.FunctionLike): {f: chunkNeqTrueV2, Label: "!="},
		},
		types.Bool: {
			// == / !=
			string("==" + types.Nil):                 {f: boolCmpNilV2, Label: "=="},
			string("!=" + types.Nil):                 {f: boolNotNilV2, Label: "!="},
			string("==" + types.Bool):                {f: boolCmpBoolV2, Label: "=="},
			string("!=" + types.Bool):                {f: boolNotBoolV2, Label: "!="},
			string("==" + types.Int):                 {f: chunkEqFalseV2, Label: "=="},
			string("!=" + types.Int):                 {f: chunkNeqTrueV2, Label: "!="},
			string("==" + types.Float):               {f: chunkEqFalseV2, Label: "=="},
			string("!=" + types.Float):               {f: chunkNeqTrueV2, Label: "!="},
			string("==" + types.String):              {f: boolCmpStringV2, Label: "=="},
			string("!=" + types.String):              {f: boolNotStringV2, Label: "!="},
			string("==" + types.Regex):               {f: chunkEqFalseV2, Label: "=="},
			string("!=" + types.Regex):               {f: chunkNeqTrueV2, Label: "!="},
			string("==" + types.Time):                {f: chunkEqFalseV2, Label: "=="},
			string("!=" + types.Time):                {f: chunkNeqTrueV2, Label: "!="},
			string("==" + types.Dict):                {f: boolCmpDictV2, Label: "=="},
			string("!=" + types.Dict):                {f: boolNotDictV2, Label: "!="},
			string("==" + types.Empty):               {f: boolCmpNilV2, Label: "=="},
			string("!=" + types.Empty):               {f: boolNotNilV2, Label: "!="},
			string("==" + types.ArrayLike):           {f: chunkEqFalseV2, Label: "=="},
			string("!=" + types.ArrayLike):           {f: chunkNeqTrueV2, Label: "!="},
			string("==" + types.Array(types.Bool)):   {f: boolCmpBoolarrayV2, Label: "=="},
			string("!=" + types.Array(types.Bool)):   {f: boolNotBoolarrayV2, Label: "!="},
			string("==" + types.Array(types.String)): {f: boolCmpStringarrayV2, Label: "=="},
			string("!=" + types.Array(types.String)): {f: boolNotStringarrayV2, Label: "!="},
			string("==" + types.MapLike):             {f: chunkEqFalseV2, Label: "=="},
			string("!=" + types.MapLike):             {f: chunkNeqTrueV2, Label: "!="},
			string("==" + types.ResourceLike):        {f: chunkEqFalseV2, Label: "=="},
			string("!=" + types.ResourceLike):        {f: chunkNeqTrueV2, Label: "!="},
			string("==" + types.FunctionLike):        {f: chunkEqFalseV2, Label: "=="},
			string("!=" + types.FunctionLike):        {f: chunkNeqTrueV2, Label: "!="},
			//
			string("&&" + types.Bool):      {f: boolAndBoolV2, Label: "&&"},
			string("||" + types.Bool):      {f: boolOrBoolV2, Label: "||"},
			string("&&" + types.Int):       {f: boolAndIntV2, Label: "&&"},
			string("||" + types.Int):       {f: boolOrIntV2, Label: "||"},
			string("&&" + types.Float):     {f: boolAndFloatV2, Label: "&&"},
			string("||" + types.Float):     {f: boolOrFloatV2, Label: "||"},
			string("&&" + types.String):    {f: boolAndStringV2, Label: "&&"},
			string("||" + types.String):    {f: boolOrStringV2, Label: "||"},
			string("&&" + types.Regex):     {f: boolAndRegexV2, Label: "&&"},
			string("||" + types.Regex):     {f: boolOrRegexV2, Label: "||"},
			string("&&" + types.Time):      {f: boolAndTimeV2, Label: "&&"},
			string("||" + types.Time):      {f: boolOrTimeV2, Label: "||"},
			string("&&" + types.Dict):      {f: boolAndDictV2, Label: "&&"},
			string("||" + types.Dict):      {f: boolOrDictV2, Label: "||"},
			string("&&" + types.ArrayLike): {f: boolAndArrayV2, Label: "&&"},
			string("||" + types.ArrayLike): {f: boolOrArrayV2, Label: "||"},
			string("&&" + types.MapLike):   {f: boolAndMapV2, Label: "&&"},
			string("||" + types.MapLike):   {f: boolOrMapV2, Label: "||"},
		},
		types.Int: {
			// == / !=
			string("==" + types.Nil):                 {f: intCmpNilV2, Label: "=="},
			string("!=" + types.Nil):                 {f: intNotNilV2, Label: "!="},
			string("==" + types.Int):                 {f: intCmpIntV2, Label: "=="},
			string("!=" + types.Int):                 {f: intNotIntV2, Label: "!="},
			string("==" + types.Float):               {f: intCmpFloatV2, Label: "=="},
			string("!=" + types.Float):               {f: intNotFloatV2, Label: "!="},
			string("==" + types.String):              {f: intCmpStringV2, Label: "=="},
			string("!=" + types.String):              {f: intNotStringV2, Label: "!="},
			string("==" + types.Regex):               {f: intCmpRegexV2, Label: "=="},
			string("!=" + types.Regex):               {f: intNotRegexV2, Label: "!="},
			string("==" + types.Dict):                {f: intCmpDictV2, Label: "=="},
			string("!=" + types.Dict):                {f: intNotDictV2, Label: "!="},
			string("==" + types.Empty):               {f: intCmpNilV2, Label: "=="},
			string("!=" + types.Empty):               {f: intNotNilV2, Label: "!="},
			string("==" + types.ArrayLike):           {f: chunkEqFalseV2, Label: "=="},
			string("!=" + types.ArrayLike):           {f: chunkNeqTrueV2, Label: "!="},
			string("==" + types.Array(types.Int)):    {f: intCmpIntarrayV2, Label: "=="},
			string("!=" + types.Array(types.Int)):    {f: intNotIntarrayV2, Label: "!="},
			string("==" + types.Array(types.Float)):  {f: intCmpFloatarrayV2, Label: "=="},
			string("!=" + types.Array(types.Float)):  {f: intNotFloatarrayV2, Label: "!="},
			string("==" + types.Array(types.String)): {f: intCmpStringarrayV2, Label: "=="},
			string("!=" + types.Array(types.String)): {f: intNotStringarrayV2, Label: "!="},
			string("+" + types.Int):                  {f: intPlusIntV2, Label: "+", Typ: types.Int},
			string("-" + types.Int):                  {f: intMinusIntV2, Label: "-", Typ: types.Int},
			string("*" + types.Int):                  {f: intTimesIntV2, Label: "*", Typ: types.Int},
			string("/" + types.Int):                  {f: intDividedIntV2, Label: "/", Typ: types.Int},
			string("+" + types.Float):                {f: intPlusFloatV2, Label: "+", Typ: types.Float},
			string("-" + types.Float):                {f: intMinusFloatV2, Label: "-", Typ: types.Float},
			string("*" + types.Float):                {f: intTimesFloatV2, Label: "*", Typ: types.Float},
			string("/" + types.Float):                {f: intDividedFloatV2, Label: "/", Typ: types.Float},
			string("+" + types.Dict):                 {f: intPlusDictV2, Label: "+", Typ: types.Float},
			string("-" + types.Dict):                 {f: intMinusDictV2, Label: "-", Typ: types.Float},
			string("*" + types.Dict):                 {f: intTimesDictV2, Label: "*", Typ: types.Float},
			string("/" + types.Dict):                 {f: intDividedDictV2, Label: "/", Typ: types.Float},
			string("*" + types.Time):                 {f: intTimesTimeV2, Label: "*", Typ: types.Time},
			string("<" + types.Int):                  {f: intLTIntV2, Label: "<"},
			string("<=" + types.Int):                 {f: intLTEIntV2, Label: "<="},
			string(">" + types.Int):                  {f: intGTIntV2, Label: ">"},
			string(">=" + types.Int):                 {f: intGTEIntV2, Label: ">="},
			string("<" + types.Float):                {f: intLTFloatV2, Label: "<"},
			string("<=" + types.Float):               {f: intLTEFloatV2, Label: "<="},
			string(">" + types.Float):                {f: intGTFloatV2, Label: ">"},
			string(">=" + types.Float):               {f: intGTEFloatV2, Label: ">="},
			string("<" + types.String):               {f: intLTStringV2, Label: "<"},
			string("<=" + types.String):              {f: intLTEStringV2, Label: "<="},
			string(">" + types.String):               {f: intGTStringV2, Label: ">"},
			string(">=" + types.String):              {f: intGTEStringV2, Label: ">="},
			string("<" + types.Dict):                 {f: intLTDictV2, Label: "<"},
			string("<=" + types.Dict):                {f: intLTEDictV2, Label: "<="},
			string(">" + types.Dict):                 {f: intGTDictV2, Label: ">"},
			string(">=" + types.Dict):                {f: intGTEDictV2, Label: ">="},
			string("&&" + types.Bool):                {f: intAndBoolV2, Label: "&&"},
			string("||" + types.Bool):                {f: intOrBoolV2, Label: "||"},
			string("&&" + types.Int):                 {f: intAndIntV2, Label: "&&"},
			string("||" + types.Int):                 {f: intOrIntV2, Label: "||"},
			string("&&" + types.Float):               {f: intAndFloatV2, Label: "&&"},
			string("||" + types.Float):               {f: intOrFloatV2, Label: "||"},
			string("&&" + types.String):              {f: intAndStringV2, Label: "&&"},
			string("||" + types.String):              {f: intOrStringV2, Label: "||"},
			string("&&" + types.Regex):               {f: intAndRegexV2, Label: "&&"},
			string("||" + types.Regex):               {f: intOrRegexV2, Label: "||"},
			string("&&" + types.Time):                {f: intAndTimeV2, Label: "&&"},
			string("||" + types.Time):                {f: intOrTimeV2, Label: "||"},
			string("&&" + types.Dict):                {f: intAndDictV2, Label: "&&"},
			string("||" + types.Dict):                {f: intOrDictV2, Label: "||"},
			string("&&" + types.ArrayLike):           {f: intAndArrayV2, Label: "&&"},
			string("||" + types.ArrayLike):           {f: intOrArrayV2, Label: "||"},
			string("&&" + types.MapLike):             {f: intAndMapV2, Label: "&&"},
			string("||" + types.MapLike):             {f: intOrMapV2, Label: "||"},
			string("inRange"):                        {f: intInRange, Label: "inRange"},
		},
		types.Float: {
			// == / !=
			string("==" + types.Nil):                 {f: floatCmpNilV2, Label: "=="},
			string("!=" + types.Nil):                 {f: floatNotNilV2, Label: "!="},
			string("==" + types.Int):                 {f: floatCmpIntV2, Label: "=="},
			string("!=" + types.Int):                 {f: floatNotIntV2, Label: "!="},
			string("==" + types.Float):               {f: floatCmpFloatV2, Label: "=="},
			string("!=" + types.Float):               {f: floatNotFloatV2, Label: "!="},
			string("==" + types.String):              {f: floatCmpStringV2, Label: "=="},
			string("!=" + types.String):              {f: floatNotStringV2, Label: "!="},
			string("==" + types.Regex):               {f: floatCmpRegexV2, Label: "=="},
			string("!=" + types.Regex):               {f: floatNotRegexV2, Label: "!="},
			string("==" + types.Dict):                {f: floatCmpDictV2, Label: "=="},
			string("!=" + types.Dict):                {f: floatNotDictV2, Label: "!="},
			string("==" + types.Empty):               {f: floatCmpNilV2, Label: "=="},
			string("!=" + types.Empty):               {f: floatNotNilV2, Label: "!="},
			string("==" + types.ArrayLike):           {f: chunkEqFalseV2, Label: "=="},
			string("!=" + types.ArrayLike):           {f: chunkNeqTrueV2, Label: "!="},
			string("==" + types.Array(types.Int)):    {f: floatCmpIntarrayV2, Label: "=="},
			string("!=" + types.Array(types.Int)):    {f: floatNotIntarrayV2, Label: "!="},
			string("==" + types.Array(types.Float)):  {f: floatCmpFloatarrayV2, Label: "=="},
			string("!=" + types.Array(types.Float)):  {f: floatNotFloatarrayV2, Label: "!="},
			string("==" + types.Array(types.String)): {f: floatCmpStringarrayV2, Label: "=="},
			string("!=" + types.Array(types.String)): {f: floatNotStringarrayV2, Label: "!="},
			string("+" + types.Int):                  {f: floatPlusIntV2, Label: "+", Typ: types.Float},
			string("-" + types.Int):                  {f: floatMinusIntV2, Label: "-", Typ: types.Float},
			string("*" + types.Int):                  {f: floatTimesIntV2, Label: "*", Typ: types.Float},
			string("/" + types.Int):                  {f: floatDividedIntV2, Label: "/", Typ: types.Float},
			string("+" + types.Float):                {f: floatPlusFloatV2, Label: "+", Typ: types.Float},
			string("-" + types.Float):                {f: floatMinusFloatV2, Label: "-", Typ: types.Float},
			string("*" + types.Float):                {f: floatTimesFloatV2, Label: "*", Typ: types.Float},
			string("/" + types.Float):                {f: floatDividedFloatV2, Label: "/", Typ: types.Float},
			string("+" + types.Dict):                 {f: floatPlusDictV2, Label: "+", Typ: types.Float},
			string("-" + types.Dict):                 {f: floatMinusDictV2, Label: "-", Typ: types.Float},
			string("*" + types.Dict):                 {f: floatTimesDictV2, Label: "*", Typ: types.Float},
			string("/" + types.Dict):                 {f: floatDividedDictV2, Label: "/", Typ: types.Float},
			string("*" + types.Time):                 {f: floatTimesTimeV2, Label: "*", Typ: types.Time},
			string("<" + types.Int):                  {f: floatLTIntV2, Label: "<"},
			string("<=" + types.Int):                 {f: floatLTEIntV2, Label: "<="},
			string(">" + types.Int):                  {f: floatGTIntV2, Label: ">"},
			string(">=" + types.Int):                 {f: floatGTEIntV2, Label: ">="},
			string("<" + types.Float):                {f: floatLTFloatV2, Label: "<"},
			string("<=" + types.Float):               {f: floatLTEFloatV2, Label: "<="},
			string(">" + types.Float):                {f: floatGTFloatV2, Label: ">"},
			string(">=" + types.Float):               {f: floatGTEFloatV2, Label: ">="},
			string("<" + types.String):               {f: floatLTStringV2, Label: "<"},
			string("<=" + types.String):              {f: floatLTEStringV2, Label: "<="},
			string(">" + types.String):               {f: floatGTStringV2, Label: ">"},
			string(">=" + types.String):              {f: floatGTEStringV2, Label: ">="},
			string("<" + types.Dict):                 {f: floatLTDictV2, Label: "<"},
			string("<=" + types.Dict):                {f: floatLTEDictV2, Label: "<="},
			string(">" + types.Dict):                 {f: floatGTDictV2, Label: ">"},
			string(">=" + types.Dict):                {f: floatGTEDictV2, Label: ">="},
			string("&&" + types.Bool):                {f: floatAndBoolV2, Label: "&&"},
			string("||" + types.Bool):                {f: floatOrBoolV2, Label: "||"},
			string("&&" + types.Int):                 {f: floatAndIntV2, Label: "&&"},
			string("||" + types.Int):                 {f: floatOrIntV2, Label: "||"},
			string("&&" + types.Float):               {f: floatAndFloatV2, Label: "&&"},
			string("||" + types.Float):               {f: floatOrFloatV2, Label: "||"},
			string("&&" + types.String):              {f: floatAndStringV2, Label: "&&"},
			string("||" + types.String):              {f: floatOrStringV2, Label: "||"},
			string("&&" + types.Regex):               {f: floatAndRegexV2, Label: "&&"},
			string("||" + types.Regex):               {f: floatOrRegexV2, Label: "||"},
			string("&&" + types.Time):                {f: floatAndTimeV2, Label: "&&"},
			string("||" + types.Time):                {f: floatOrTimeV2, Label: "||"},
			string("&&" + types.Dict):                {f: floatAndDictV2, Label: "&&"},
			string("||" + types.Dict):                {f: floatOrDictV2, Label: "||"},
			string("&&" + types.ArrayLike):           {f: floatAndArrayV2, Label: "&&"},
			string("||" + types.ArrayLike):           {f: floatOrArrayV2, Label: "||"},
			string("&&" + types.MapLike):             {f: floatAndMapV2, Label: "&&"},
			string("||" + types.MapLike):             {f: floatOrMapV2, Label: "&&"},
			string("inRange"):                        {f: floatInRange, Label: "inRange"},
		},
		types.String: {
			// == / !=
			string("==" + types.Nil):                 {f: stringCmpNilV2, Label: "=="},
			string("!=" + types.Nil):                 {f: stringNotNilV2, Label: "!="},
			string("==" + types.Empty):               {f: stringCmpEmptyV2, Label: "=="},
			string("!=" + types.Empty):               {f: stringNotEmptyV2, Label: "!="},
			string("==" + types.String):              {f: stringCmpStringV2, Label: "=="},
			string("!=" + types.String):              {f: stringNotStringV2, Label: "!="},
			string("==" + types.Regex):               {f: stringCmpRegexV2, Label: "=="},
			string("!=" + types.Regex):               {f: stringNotRegexV2, Label: "!="},
			string("==" + types.Bool):                {f: stringCmpBoolV2, Label: "=="},
			string("!=" + types.Bool):                {f: stringNotBoolV2, Label: "!="},
			string("==" + types.Int):                 {f: stringCmpIntV2, Label: "=="},
			string("!=" + types.Int):                 {f: stringNotIntV2, Label: "!="},
			string("==" + types.Float):               {f: stringCmpFloatV2, Label: "=="},
			string("!=" + types.Float):               {f: stringNotFloatV2, Label: "!="},
			string("==" + types.Dict):                {f: stringCmpDictV2, Label: "=="},
			string("!=" + types.Dict):                {f: stringNotDictV2, Label: "!="},
			string("==" + types.Version):             {f: versionCmpVersion, Label: "=="},
			string("!=" + types.Version):             {f: versionNotVersion, Label: "!="},
			string("==" + types.IP):                  {f: ipCmpIP, Label: "=="},
			string("!=" + types.IP):                  {f: ipNotIP, Label: "!="},
			string("==" + types.ArrayLike):           {f: chunkEqFalseV2, Label: "=="},
			string("!=" + types.ArrayLike):           {f: chunkNeqTrueV2, Label: "!="},
			string("==" + types.Array(types.String)): {f: stringCmpStringarrayV2, Label: "=="},
			string("!=" + types.Array(types.String)): {f: stringNotStringarrayV2, Label: "!="},
			string("==" + types.Array(types.Bool)):   {f: stringCmpBoolarrayV2, Label: "=="},
			string("!=" + types.Array(types.Bool)):   {f: stringNotBoolarrayV2, Label: "!="},
			string("==" + types.Array(types.Int)):    {f: stringCmpIntarrayV2, Label: "=="},
			string("!=" + types.Array(types.Int)):    {f: stringNotIntarrayV2, Label: "!="},
			string("==" + types.Array(types.Float)):  {f: stringCmpFloatarrayV2, Label: "=="},
			string("!=" + types.Array(types.Float)):  {f: stringNotFloatarrayV2, Label: "!="},
			string("<" + types.Int):                  {f: stringLTIntV2, Label: "<"},
			string("<=" + types.Int):                 {f: stringLTEIntV2, Label: "<="},
			string(">" + types.Int):                  {f: stringGTIntV2, Label: ">"},
			string(">=" + types.Int):                 {f: stringGTEIntV2, Label: ">="},
			string("<" + types.Float):                {f: stringLTFloatV2, Label: "<"},
			string("<=" + types.Float):               {f: stringLTEFloatV2, Label: "<="},
			string(">" + types.Float):                {f: stringGTFloatV2, Label: ">"},
			string(">=" + types.Float):               {f: stringGTEFloatV2, Label: ">="},
			string("<" + types.String):               {f: stringLTStringV2, Label: "<"},
			string("<=" + types.String):              {f: stringLTEStringV2, Label: "<="},
			string(">" + types.String):               {f: stringGTStringV2, Label: ">"},
			string(">=" + types.String):              {f: stringGTEStringV2, Label: ">="},
			string("<" + types.Dict):                 {f: stringLTDictV2, Label: "<"},
			string("<=" + types.Dict):                {f: stringLTEDictV2, Label: "<="},
			string(">" + types.Dict):                 {f: stringGTDictV2, Label: ">"},
			string(">=" + types.Dict):                {f: stringGTEDictV2, Label: ">="},
			string("<" + types.Version):              {f: versionLTversion, Label: "<"},
			string(">" + types.Version):              {f: versionGTversion, Label: ">"},
			string("<=" + types.Version):             {f: versionLTEversion, Label: "<="},
			string(">=" + types.Version):             {f: versionGTEversion, Label: ">="},
			string("&&" + types.Bool):                {f: stringAndBoolV2, Label: "&&"},
			string("||" + types.Bool):                {f: stringOrBoolV2, Label: "||"},
			string("&&" + types.Int):                 {f: stringAndIntV2, Label: "&&"},
			string("||" + types.Int):                 {f: stringOrIntV2, Label: "||"},
			string("&&" + types.Float):               {f: stringAndFloatV2, Label: "&&"},
			string("||" + types.Float):               {f: stringOrFloatV2, Label: "||"},
			string("&&" + types.String):              {f: stringAndStringV2, Label: "&&"},
			string("||" + types.String):              {f: stringOrStringV2, Label: "||"},
			string("&&" + types.Regex):               {f: stringAndRegexV2, Label: "&&"},
			string("||" + types.Regex):               {f: stringOrRegexV2, Label: "||"},
			string("&&" + types.Time):                {f: stringAndTimeV2, Label: "&&"},
			string("||" + types.Time):                {f: stringOrTimeV2, Label: "||"},
			string("&&" + types.Dict):                {f: stringAndDictV2, Label: "&&"},
			string("||" + types.Dict):                {f: stringOrDictV2, Label: "||"},
			string("&&" + types.ArrayLike):           {f: stringAndArrayV2, Label: "&&"},
			string("||" + types.ArrayLike):           {f: stringOrArrayV2, Label: "||"},
			string("&&" + types.MapLike):             {f: stringAndMapV2, Label: "&&"},
			string("||" + types.MapLike):             {f: stringOrMapV2, Label: "&&"},
			string("+" + types.String):               {f: stringPlusStringV2, Label: "+"},
			// fields
			string("contains" + types.String):              {f: stringContainsString, Label: "contains"},
			string("contains" + types.Array(types.String)): {f: stringContainsArrayString, Label: "contains"},
			string("contains" + types.Dict):                {f: stringContainsDict, Label: "contains"},
			string("contains" + types.Array(types.Dict)):   {f: stringContainsArrayDict, Label: "contains"},
			string("contains" + types.Int):                 {f: stringContainsInt, Label: "contains"},
			string("contains" + types.Array(types.Int)):    {f: stringContainsArrayInt, Label: "contains"},
			string("contains" + types.Regex):               {f: stringContainsRegex, Label: "contains"},
			string("contains" + types.Array(types.Regex)):  {f: stringContainsArrayRegex, Label: "contains"},
			string("in"):        {f: stringInArray, Label: "in"},
			string("notIn"):     {f: stringNotInArray, Label: "in"},
			string("inRange"):   {f: stringInRange, Label: "inRange"},
			string("find"):      {f: stringFindV2, Label: "find"},
			string("camelcase"): {f: stringCamelcaseV2, Label: "camelcase"},
			string("downcase"):  {f: stringDowncaseV2, Label: "downcase"},
			string("upcase"):    {f: stringUpcaseV2, Label: "upcase"},
			string("length"):    {f: stringLengthV2, Label: "length"},
			string("lines"):     {f: stringLinesV2, Label: "lines"},
			string("split"):     {f: stringSplitV2, Label: "split"},
			string("trim"):      {f: stringTrimV2, Label: "trim"},
			string("json"):      {f: stringJsonV2, Label: "json"},
		},
		types.StringSlice: {
			// TODO: implement the remaining calls for this type
			// string("==" + types.Nil):                 {f: chunkEqFalseV2, Label: "=="},
			// string("!=" + types.Nil):                 {f: chunkNeqFalseV2, Label: "!="},
			string("==" + types.String): {f: stringsliceEqString, Label: "=="},
			// string("!=" + types.String):              {f: stringNotStringV2, Label: "!="},
			// string("==" + types.Regex):               {f: stringCmpRegexV2, Label: "=="},
			// string("!=" + types.Regex):               {f: stringNotRegexV2, Label: "!="},
			// string("==" + types.Bool):                {f: stringCmpBoolV2, Label: "=="},
			// string("!=" + types.Bool):                {f: stringNotBoolV2, Label: "!="},
			// string("==" + types.Int):                 {f: stringCmpIntV2, Label: "=="},
			// string("!=" + types.Int):                 {f: stringNotIntV2, Label: "!="},
			// string("==" + types.Float):               {f: stringCmpFloatV2, Label: "=="},
			// string("!=" + types.Float):               {f: stringNotFloatV2, Label: "!="},
			string("==" + types.Dict): {f: stringsliceEqDict, Label: "=="},
			// string("!=" + types.Dict):                {f: stringNotDictV2, Label: "!="},
			string("==" + types.Array(types.String)): {f: stringsliceEqArrayString, Label: "=="},
		},
		types.Regex: {
			// == / !=
			string("==" + types.Nil):                 {f: stringCmpNilV2, Label: "=="},
			string("!=" + types.Nil):                 {f: stringNotNilV2, Label: "!="},
			string("==" + types.Empty):               {f: stringCmpEmptyV2, Label: "=="},
			string("!=" + types.Empty):               {f: stringNotEmptyV2, Label: "!="},
			string("==" + types.Regex):               {f: stringCmpStringV2, Label: "=="},
			string("!=" + types.Regex):               {f: stringNotStringV2, Label: "!="},
			string("==" + types.Bool):                {f: chunkEqFalseV2, Label: "=="},
			string("!=" + types.Bool):                {f: chunkNeqFalseV2, Label: "!="},
			string("==" + types.Int):                 {f: regexCmpIntV2, Label: "=="},
			string("!=" + types.Int):                 {f: regexNotIntV2, Label: "!="},
			string("==" + types.Float):               {f: regexCmpFloatV2, Label: "=="},
			string("!=" + types.Float):               {f: regexNotFloatV2, Label: "!="},
			string("==" + types.Dict):                {f: regexCmpDictV2, Label: "=="},
			string("!=" + types.Dict):                {f: regexNotDictV2, Label: "!="},
			string("==" + types.String):              {f: regexCmpStringV2, Label: "=="},
			string("!=" + types.String):              {f: regexNotStringV2, Label: "!="},
			string("==" + types.ArrayLike):           {f: chunkEqFalseV2, Label: "=="},
			string("!=" + types.ArrayLike):           {f: chunkNeqTrueV2, Label: "!="},
			string("==" + types.Array(types.Regex)):  {f: stringCmpStringarrayV2, Label: "=="},
			string("!=" + types.Array(types.Regex)):  {f: stringNotStringarrayV2, Label: "!="},
			string("==" + types.Array(types.Int)):    {f: regexCmpIntarrayV2, Label: "=="},
			string("!=" + types.Array(types.Int)):    {f: regexNotIntarrayV2, Label: "!="},
			string("==" + types.Array(types.Float)):  {f: regexCmpFloatarrayV2, Label: "=="},
			string("!=" + types.Array(types.Float)):  {f: regexNotFloatarrayV2, Label: "!="},
			string("==" + types.Array(types.String)): {f: regexCmpStringarrayV2, Label: "=="},
			string("!=" + types.Array(types.String)): {f: regexNotStringarrayV2, Label: "!="},
			string("&&" + types.Bool):                {f: regexAndBoolV2, Label: "&&"},
			string("||" + types.Bool):                {f: regexOrBoolV2, Label: "||"},
			string("&&" + types.Int):                 {f: regexAndIntV2, Label: "&&"},
			string("||" + types.Int):                 {f: regexOrIntV2, Label: "||"},
			string("&&" + types.Float):               {f: regexAndFloatV2, Label: "&&"},
			string("||" + types.Float):               {f: regexOrFloatV2, Label: "||"},
			string("&&" + types.String):              {f: regexAndStringV2, Label: "&&"},
			string("||" + types.String):              {f: regexOrStringV2, Label: "||"},
			string("&&" + types.Regex):               {f: regexAndRegexV2, Label: "&&"},
			string("||" + types.Regex):               {f: regexOrRegexV2, Label: "||"},
			string("&&" + types.Time):                {f: regexAndTimeV2, Label: "&&"},
			string("||" + types.Time):                {f: regexOrTimeV2, Label: "||"},
			string("&&" + types.Dict):                {f: regexAndDictV2, Label: "&&"},
			string("||" + types.Dict):                {f: regexOrDictV2, Label: "||"},
			string("&&" + types.ArrayLike):           {f: regexAndArrayV2, Label: "&&"},
			string("||" + types.ArrayLike):           {f: regexOrArrayV2, Label: "||"},
			string("&&" + types.MapLike):             {f: regexAndMapV2, Label: "&&"},
			string("||" + types.MapLike):             {f: regexOrMapV2, Label: "&&"},
		},
		types.Time: {
			string("==" + types.Nil):       {f: timeCmpNilV2, Label: "=="},
			string("!=" + types.Nil):       {f: timeNotNilV2, Label: "!="},
			string("==" + types.Empty):     {f: timeCmpNilV2, Label: "=="},
			string("!=" + types.Empty):     {f: timeNotNilV2, Label: "!="},
			string("==" + types.Time):      {f: timeCmpTimeV2, Label: "=="},
			string("!=" + types.Time):      {f: timeNotTimeV2, Label: "!="},
			string("<" + types.Time):       {f: timeLTTimeV2, Label: "<"},
			string("<=" + types.Time):      {f: timeLTETimeV2, Label: "<="},
			string(">" + types.Time):       {f: timeGTTimeV2, Label: ">"},
			string(">=" + types.Time):      {f: timeGTETimeV2, Label: ">="},
			string("&&" + types.Bool):      {f: timeAndBoolV2, Label: "&&"},
			string("||" + types.Bool):      {f: timeOrBoolV2, Label: "||"},
			string("&&" + types.Int):       {f: timeAndIntV2, Label: "&&"},
			string("||" + types.Int):       {f: timeOrIntV2, Label: "||"},
			string("&&" + types.Float):     {f: timeAndFloatV2, Label: "&&"},
			string("||" + types.Float):     {f: timeOrFloatV2, Label: "||"},
			string("&&" + types.String):    {f: timeAndStringV2, Label: "&&"},
			string("||" + types.String):    {f: timeOrStringV2, Label: "||"},
			string("&&" + types.Regex):     {f: timeAndRegexV2, Label: "&&"},
			string("||" + types.Regex):     {f: timeOrRegexV2, Label: "||"},
			string("&&" + types.Time):      {f: timeAndTimeV2, Label: "&&"},
			string("||" + types.Time):      {f: timeOrTimeV2, Label: "||"},
			string("&&" + types.Dict):      {f: timeAndDictV2, Label: "&&"},
			string("||" + types.Dict):      {f: timeOrDictV2, Label: "||"},
			string("&&" + types.ArrayLike): {f: timeAndArrayV2, Label: "&&"},
			string("||" + types.ArrayLike): {f: timeOrArrayV2, Label: "||"},
			string("&&" + types.MapLike):   {f: timeAndMapV2, Label: "&&"},
			string("||" + types.MapLike):   {f: timeOrMapV2, Label: "||"},
			string("-" + types.Time):       {f: timeMinusTimeV2, Label: "-"},
			string("+" + types.Time):       {f: timePlusTimeV2, Label: "+"},
			string("*" + types.Int):        {f: timeTimesIntV2, Label: "*", Typ: types.Time},
			string("*" + types.Float):      {f: timeTimesFloatV2, Label: "*", Typ: types.Time},
			string("*" + types.Dict):       {f: timeTimesDictV2, Label: "*", Typ: types.Time},
			// fields
			string("seconds"): {f: timeSecondsV2, Label: "seconds"},
			string("minutes"): {f: timeMinutesV2, Label: "minutes"},
			string("hours"):   {f: timeHoursV2, Label: "hours"},
			string("days"):    {f: timeDaysV2, Label: "days"},
			string("unix"):    {f: timeUnixV2, Label: "unix"},
			string("inRange"): {f: timeInRange, Label: "inRange"},
		},
		types.AssetLike: {
			string("==" + types.Nil):   {f: assetCmpNilV2, Label: "=="},
			string("!=" + types.Nil):   {f: assetNotNilV2, Label: "!="},
			string("==" + types.Empty): {f: assetCmpNilV2, Label: "=="},
			string("!=" + types.Empty): {f: assetNotNilV2, Label: "!="},
			AssetRootChunkID:           {f: runAssetRoot, Label: AssetRootChunkID},
		},
		types.Dict: {
			string("==" + types.Nil):                 {f: dictCmpNilV2, Label: "=="},
			string("!=" + types.Nil):                 {f: dictNotNilV2, Label: "!="},
			string("==" + types.Empty):               {f: dictCmpEmpty, Label: "=="},
			string("!=" + types.Empty):               {f: dictNotEmpty, Label: "!="},
			string("==" + types.Bool):                {f: dictCmpBoolV2, Label: "=="},
			string("!=" + types.Bool):                {f: dictNotBoolV2, Label: "!="},
			string("==" + types.Int):                 {f: dictCmpIntV2, Label: "=="},
			string("!=" + types.Int):                 {f: dictNotIntV2, Label: "!="},
			string("==" + types.Float):               {f: dictCmpFloatV2, Label: "=="},
			string("!=" + types.Float):               {f: dictNotFloatV2, Label: "!="},
			string("==" + types.Dict):                {f: dictCmpDictV2, Label: "=="},
			string("!=" + types.Dict):                {f: dictNotDictV2, Label: "!="},
			string("==" + types.String):              {f: dictCmpStringV2, Label: "=="},
			string("!=" + types.String):              {f: dictNotStringV2, Label: "!="},
			string("==" + types.Regex):               {f: dictCmpRegexV2, Label: "=="},
			string("!=" + types.Regex):               {f: dictNotRegexV2, Label: "!="},
			string("==" + types.Version):             {f: versionCmpVersion, Label: "=="},
			string("!=" + types.Version):             {f: versionNotVersion, Label: "!="},
			string("==" + types.IP):                  {f: ipCmpIP, Label: "=="},
			string("!=" + types.IP):                  {f: ipNotIP, Label: "!="},
			string("==" + types.ArrayLike):           {f: dictCmpArrayV2, Label: "=="},
			string("!=" + types.ArrayLike):           {f: dictNotArrayV2, Label: "!="},
			string("==" + types.Array(types.String)): {f: dictCmpStringarrayV2, Label: "=="},
			string("!=" + types.Array(types.String)): {f: dictNotStringarrayV2, Label: "!="},
			string("==" + types.Array(types.Regex)):  {f: dictCmpRegexarrayV2, Label: "=="},
			string("!=" + types.Array(types.Regex)):  {f: dictNotRegexarrayV2, Label: "!="},
			string("==" + types.Array(types.Bool)):   {f: dictCmpBoolarrayV2, Label: "=="},
			string("!=" + types.Array(types.Bool)):   {f: dictNotBoolarrayV2, Label: "!="},
			string("==" + types.Array(types.Int)):    {f: dictCmpIntarrayV2, Label: "=="},
			string("!=" + types.Array(types.Int)):    {f: dictNotIntarrayV2, Label: "!="},
			string("==" + types.Array(types.Float)):  {f: dictCmpFloatarrayV2, Label: "=="},
			string("!=" + types.Array(types.Float)):  {f: dictNotFloatarrayV2, Label: "!="},
			string("<" + types.Int):                  {f: dictLTIntV2, Label: "<"},
			string("<=" + types.Int):                 {f: dictLTEIntV2, Label: "<="},
			string(">" + types.Int):                  {f: dictGTIntV2, Label: ">"},
			string(">=" + types.Int):                 {f: dictGTEIntV2, Label: ">="},
			string("<" + types.Float):                {f: dictLTFloatV2, Label: "<"},
			string("<=" + types.Float):               {f: dictLTEFloatV2, Label: "<="},
			string(">" + types.Float):                {f: dictGTFloatV2, Label: ">"},
			string(">=" + types.Float):               {f: dictGTEFloatV2, Label: ">="},
			string("<" + types.String):               {f: dictLTStringV2, Label: "<"},
			string("<=" + types.String):              {f: dictLTEStringV2, Label: "<="},
			string(">" + types.String):               {f: dictGTStringV2, Label: ">"},
			string(">=" + types.String):              {f: dictGTEStringV2, Label: ">="},
			string("<" + types.Dict):                 {f: dictLTDictV2, Label: "<"},
			string("<=" + types.Dict):                {f: dictLTEDictV2, Label: "<="},
			string(">" + types.Dict):                 {f: dictGTDictV2, Label: ">"},
			string(">=" + types.Dict):                {f: dictGTEDictV2, Label: ">="},
			string("<" + types.Version):              {f: versionLTversion, Label: "<"},
			string(">" + types.Version):              {f: versionGTversion, Label: ">"},
			string("<=" + types.Version):             {f: versionLTEversion, Label: "<="},
			string(">=" + types.Version):             {f: versionGTEversion, Label: ">="},
			string("&&" + types.Bool):                {f: dictAndBoolV2, Label: "&&"},
			string("||" + types.Bool):                {f: dictOrBoolV2, Label: "||"},
			string("&&" + types.Int):                 {f: dictAndIntV2, Label: "&&"},
			string("||" + types.Int):                 {f: dictOrIntV2, Label: "||"},
			string("&&" + types.Float):               {f: dictAndFloatV2, Label: "&&"},
			string("||" + types.Float):               {f: dictOrFloatV2, Label: "||"},
			string("&&" + types.String):              {f: dictAndStringV2, Label: "&&"},
			string("||" + types.String):              {f: dictOrStringV2, Label: "||"},
			string("&&" + types.Regex):               {f: dictAndRegexV2, Label: "&&"},
			string("||" + types.Regex):               {f: dictOrRegexV2, Label: "||"},
			string("&&" + types.Time):                {f: dictAndTimeV2, Label: "&&"},
			string("||" + types.Time):                {f: dictOrTimeV2, Label: "||"},
			string("&&" + types.Dict):                {f: dictAndDictV2, Label: "&&"},
			string("||" + types.Dict):                {f: dictOrDictV2, Label: "||"},
			string("&&" + types.ArrayLike):           {f: dictAndArrayV2, Label: "&&"},
			string("||" + types.ArrayLike):           {f: dictOrArrayV2, Label: "||"},
			string("&&" + types.MapLike):             {f: dictAndMapV2, Label: "&&"},
			string("||" + types.MapLike):             {f: dictOrMapV2, Label: "||"},
			string("+" + types.String):               {f: dictPlusStringV2, Label: "+"},
			string("+" + types.Int):                  {f: dictPlusIntV2, Label: "+"},
			string("-" + types.Int):                  {f: dictMinusIntV2, Label: "-"},
			string("*" + types.Int):                  {f: dictTimesIntV2, Label: "*"},
			string("/" + types.Int):                  {f: dictDividedIntV2, Label: "/"},
			string("+" + types.Float):                {f: dictPlusFloatV2, Label: "+"},
			string("-" + types.Float):                {f: dictMinusFloatV2, Label: "-"},
			string("*" + types.Float):                {f: dictTimesFloatV2, Label: "*"},
			string("/" + types.Float):                {f: dictDividedFloatV2, Label: "/"},
			string("*" + types.Time):                 {f: dictTimesTimeV2, Label: "*"},
			// fields
			"[]":                              {f: dictGetIndex},
			"[]?":                             {f: dictGetIndex},
			"first":                           {f: dictGetFirstIndexV2},
			"last":                            {f: dictGetLastIndexV2},
			"{}":                              {f: dictBlockCallV2},
			"length":                          {f: dictLengthV2},
			"inRange":                         {f: dictInRange},
			"camelcase":                       {f: dictCamelcaseV2, Label: "camelcase"},
			"downcase":                        {f: dictDowncaseV2, Label: "downcase"},
			"upcase":                          {f: dictUpcaseV2, Label: "upcase"},
			"lines":                           {f: dictLinesV2, Label: "lines"},
			"split":                           {f: dictSplitV2, Label: "split"},
			"trim":                            {f: dictTrimV2, Label: "trim"},
			"json":                            {f: dictJsonV2, Label: "json"},
			"keys":                            {f: dictKeysV2, Label: "keys"},
			"values":                          {f: dictValuesV2, Label: "values"},
			"where":                           {f: dictWhere, Label: "where"},
			"sample":                          {f: dictSample, Label: "sample"},
			"recurse":                         {f: dictRecurse, Label: "recurse"},
			"$whereNot":                       {f: dictWhereNot},
			"$all":                            {f: dictAllV2},
			"$none":                           {f: dictNoneV2},
			"$any":                            {f: dictAnyV2},
			"$one":                            {f: dictOneV2},
			"map":                             {f: dictMapV2},
			"flat":                            {f: dictFlat},
			"difference":                      {f: dictDifferenceV2},
			"containsAll":                     {f: dictContainsAll},
			"containsNone":                    {f: dictContainsNone},
			string("contains" + types.String): {f: dictContainsStringV2, Label: "contains"},
			string("contains" + types.Array(types.String)): {f: dictContainsArrayStringV2, Label: "contains"},
			string("contains" + types.Dict):                {f: dictContainsDict, Label: "contains"},
			string("contains" + types.Array(types.Dict)):   {f: dictContainsArrayDict, Label: "contains"},
			string("contains" + types.Int):                 {f: dictContainsIntV2, Label: "contains"},
			string("contains" + types.Array(types.Int)):    {f: dictContainsArrayIntV2, Label: "contains"},
			string("contains" + types.Regex):               {f: dictContainsRegex, Label: "contains"},
			string("contains" + types.Array(types.Regex)):  {f: dictContainsArrayRegex, Label: "contains"},
			"in":           {f: dictIn, Label: "in"},
			"notIn":        {f: dictNotIn, Label: "notIn"},
			string("find"): {f: dictFindV2, Label: "find"},
		},
		types.Version: {
			string("==" + types.Nil):     {f: stringCmpNilV2, Label: "=="},
			string("!=" + types.Nil):     {f: stringNotNilV2, Label: "!="},
			string("==" + types.Empty):   {f: stringCmpEmptyV2, Label: "=="},
			string("!=" + types.Empty):   {f: stringNotEmptyV2, Label: "!="},
			string("==" + types.Version): {f: versionCmpVersion, Label: "=="},
			string("!=" + types.Version): {f: versionNotVersion, Label: "!="},
			string("<" + types.Version):  {f: versionLTversion, Label: "<"},
			string(">" + types.Version):  {f: versionGTversion, Label: ">"},
			string("<=" + types.Version): {f: versionLTEversion, Label: "<="},
			string(">=" + types.Version): {f: versionGTEversion, Label: ">="},
			string("==" + types.String):  {f: versionCmpVersion, Label: "=="},
			string("!=" + types.String):  {f: versionNotVersion, Label: "!="},
			string("<" + types.String):   {f: versionLTversion, Label: "<"},
			string(">" + types.String):   {f: versionGTversion, Label: ">"},
			string("<=" + types.String):  {f: versionLTEversion, Label: "<="},
			string(">=" + types.String):  {f: versionGTEversion, Label: ">="},
			"epoch":                      {f: versionEpoch},
			"inRange":                    {f: versionInRange, Label: "inRange"},
		},
		types.IP: {
			string("==" + types.Nil):   {f: stringCmpNilV2, Label: "=="},
			string("!=" + types.Nil):   {f: stringNotNilV2, Label: "!="},
			string("==" + types.Empty): {f: stringCmpEmptyV2, Label: "=="},
			string("!=" + types.Empty): {f: stringNotEmptyV2, Label: "!="},
			string("==" + types.IP):    {f: ipCmpIP, Label: "=="},
			string("!=" + types.IP):    {f: ipNotIP, Label: "!="},
			"address":                  {f: ipAddress},
			"cidr":                     {f: ipCIDR},
			"inRange":                  {f: ipInRange},
			"isPublic":                 {f: ipIsPublic},
			"isUnspecified":            {f: ipUnspecified},
			"prefix":                   {f: ipPrefix},
			"prefixLength":             {f: ipPrefixLength},
			"subnet":                   {f: ipSubnet},
			"suffix":                   {f: ipSuffix},
			"version":                  {f: ipVersion},
		},
		types.ArrayLike: {
			"[]":                       {f: arrayGetIndexV2},
			"first":                    {f: arrayGetFirstIndexV2},
			"last":                     {f: arrayGetLastIndexV2},
			"{}":                       {f: arrayBlockListV2},
			"${}":                      {f: arrayBlockV2},
			"length":                   {f: arrayLengthV2},
			"where":                    {f: arrayWhereV2},
			"$whereNot":                {f: arrayWhereNotV2},
			"sample":                   {f: arraySample},
			"$all":                     {f: arrayAllV2},
			"$none":                    {f: arrayNoneV2},
			"$any":                     {f: arrayAnyV2},
			"$one":                     {f: arrayOneV2},
			"map":                      {f: arrayMapV2},
			"flat":                     {f: arrayFlat},
			"reverse":                  {f: arrayReverse},
			"join":                     {f: arrayJoin},
			"duplicates":               {f: arrayDuplicatesV2},
			"fieldDuplicates":          {f: arrayFieldDuplicatesV2},
			"unique":                   {f: arrayUniqueV2},
			"difference":               {f: arrayDifferenceV2},
			"in":                       {f: anyArrayInStringArray},
			"notIn":                    {f: anyArrayNotInStringArray},
			"containsAll":              {f: arrayContainsAll},
			"containsNone":             {f: arrayContainsNone},
			"==":                       {Compiler: compileArrayOpArray("=="), f: tarrayCmpTarrayV2, Label: "=="},
			"!=":                       {Compiler: compileArrayOpArray("!="), f: tarrayNotTarrayV2, Label: "!="},
			"==" + string(types.Nil):   {f: arrayCmpNilV2},
			"!=" + string(types.Nil):   {f: arrayNotNilV2},
			"==" + string(types.Empty): {f: arrayCmpEmpty},
			"!=" + string(types.Empty): {f: arrayNotEmpty},
			"&&":                       {Compiler: compileLogicalArrayOp(types.ArrayLike, "&&")},
			"||":                       {Compiler: compileLogicalArrayOp(types.ArrayLike, "||")},
			"+":                        {Compiler: compileArrayOpArray("+"), f: tarrayConcatTarrayV2, Label: "+"},
			"-":                        {Compiler: compileArrayOpArray("-"), f: tarrayDeleteTarrayV2, Label: "-"},
			// logical operations []<T> -- K
			string(types.Any + "&&" + types.Bool):      {f: arrayAndBoolV2, Label: "&&"},
			string(types.Any + "||" + types.Bool):      {f: arrayOrBoolV2, Label: "||"},
			string(types.Any + "&&" + types.Int):       {f: arrayAndIntV2, Label: "&&"},
			string(types.Any + "||" + types.Int):       {f: arrayOrIntV2, Label: "||"},
			string(types.Any + "&&" + types.Float):     {f: arrayAndFloatV2, Label: "&&"},
			string(types.Any + "||" + types.Float):     {f: arrayOrFloatV2, Label: "||"},
			string(types.Any + "&&" + types.String):    {f: arrayAndStringV2, Label: "&&"},
			string(types.Any + "||" + types.String):    {f: arrayOrStringV2, Label: "||"},
			string(types.Any + "&&" + types.Regex):     {f: arrayAndRegexV2, Label: "&&"},
			string(types.Any + "||" + types.Regex):     {f: arrayOrRegexV2, Label: "||"},
			string(types.Any + "&&" + types.ArrayLike): {f: arrayAndArrayV2, Label: "&&"},
			string(types.Any + "||" + types.ArrayLike): {f: arrayOrArrayV2, Label: "||"},
			string(types.Any + "&&" + types.MapLike):   {f: arrayAndMapV2, Label: "&&"},
			string(types.Any + "||" + types.MapLike):   {f: arrayOrMapV2, Label: "||"},
			// []T -- []T
			string(types.Bool + "==" + types.Array(types.Bool)):     {f: boolarrayCmpBoolarrayV2, Label: "=="},
			string(types.Bool + "!=" + types.Array(types.Bool)):     {f: boolarrayNotBoolarrayV2, Label: "!="},
			string(types.Int + "==" + types.Array(types.Int)):       {f: intarrayCmpIntarrayV2, Label: "=="},
			string(types.Int + "!=" + types.Array(types.Int)):       {f: intarrayNotIntarrayV2, Label: "!="},
			string(types.Float + "==" + types.Array(types.Float)):   {f: floatarrayCmpFloatarrayV2, Label: "=="},
			string(types.Float + "!=" + types.Array(types.Float)):   {f: floatarrayNotFloatarrayV2, Label: "!="},
			string(types.String + "==" + types.Array(types.String)): {f: stringarrayCmpStringarrayV2, Label: "=="},
			string(types.String + "!=" + types.Array(types.String)): {f: stringarrayNotStringarrayV2, Label: "!="},
			string(types.Regex + "==" + types.Array(types.Regex)):   {f: stringarrayCmpStringarrayV2, Label: "=="},
			string(types.Regex + "!=" + types.Array(types.Regex)):   {f: stringarrayNotStringarrayV2, Label: "!="},
			// []T -- T
			string(types.Bool + "==" + types.Bool):     {f: boolarrayCmpBoolV2, Label: "=="},
			string(types.Bool + "!=" + types.Bool):     {f: boolarrayNotBoolV2, Label: "!="},
			string(types.Int + "==" + types.Int):       {f: intarrayCmpIntV2, Label: "=="},
			string(types.Int + "!=" + types.Int):       {f: intarrayNotIntV2, Label: "!="},
			string(types.Float + "==" + types.Float):   {f: floatarrayCmpFloatV2, Label: "=="},
			string(types.Float + "!=" + types.Float):   {f: floatarrayNotFloatV2, Label: "!="},
			string(types.String + "==" + types.String): {f: stringarrayCmpStringV2, Label: "=="},
			string(types.String + "!=" + types.String): {f: stringarrayNotStringV2, Label: "!="},
			string(types.Regex + "==" + types.Regex):   {f: stringarrayCmpStringV2, Label: "=="},
			string(types.Regex + "!=" + types.Regex):   {f: stringarrayNotStringV2, Label: "!="},
			// []int/float
			string(types.Int + "==" + types.Float): {f: intarrayCmpFloatV2, Label: "=="},
			string(types.Int + "!=" + types.Float): {f: intarrayNotFloatV2, Label: "!="},
			string(types.Float + "==" + types.Int): {f: floatarrayCmpIntV2, Label: "=="},
			string(types.Float + "!=" + types.Int): {f: floatarrayNotIntV2, Label: "!="},
			// []string -- T
			string(types.String + "==" + types.Bool):  {f: stringarrayCmpBoolV2, Label: "=="},
			string(types.String + "!=" + types.Bool):  {f: stringarrayNotBoolV2, Label: "!="},
			string(types.String + "==" + types.Int):   {f: stringarrayCmpIntV2, Label: "=="},
			string(types.String + "!=" + types.Int):   {f: stringarrayNotIntV2, Label: "!="},
			string(types.String + "==" + types.Float): {f: stringarrayCmpFloatV2, Label: "=="},
			string(types.String + "!=" + types.Float): {f: stringarrayNotFloatV2, Label: "!="},
			// []T -- string
			string(types.Bool + "==" + types.String):  {f: boolarrayCmpStringV2, Label: "=="},
			string(types.Bool + "!=" + types.String):  {f: boolarrayNotStringV2, Label: "!="},
			string(types.Int + "==" + types.String):   {f: intarrayCmpStringV2, Label: "=="},
			string(types.Int + "!=" + types.String):   {f: intarrayNotStringV2, Label: "!="},
			string(types.Float + "==" + types.String): {f: floatarrayCmpStringV2, Label: "=="},
			string(types.Float + "!=" + types.String): {f: floatarrayNotStringV2, Label: "!="},
			// []T -- regex
			string(types.Int + "==" + types.Regex):    {f: intarrayCmpRegexV2, Label: "=="},
			string(types.Int + "!=" + types.Regex):    {f: intarrayNotRegexV2, Label: "!="},
			string(types.Float + "==" + types.Regex):  {f: floatarrayCmpRegexV2, Label: "=="},
			string(types.Float + "!=" + types.Regex):  {f: floatarrayNotRegexV2, Label: "!="},
			string(types.String + "==" + types.Regex): {f: stringarrayCmpRegexV2, Label: "=="},
			string(types.String + "!=" + types.Regex): {f: stringarrayNotRegexV2, Label: "!="},
			// NOTE: the following functions are internal ONLY!
			// We have not yet decided if and how these may be exposed to users
			"notEmpty": {f: arrayNotEmptyV2},
		},
		types.MapLike: {
			"[]":                       {f: mapGetIndex},
			"[]?":                      {f: mapGetIndex},
			"length":                   {f: mapLengthV2},
			"where":                    {f: mapWhereV2},
			"$whereNot":                {f: mapWhereNotV2},
			"sample":                   {f: mapSample},
			"$any":                     {f: mapAny},
			"$one":                     {f: mapOne},
			"$none":                    {f: mapNone},
			"$all":                     {f: mapAll},
			"{}":                       {f: mapBlockCallV2},
			"keys":                     {f: mapKeysV2, Label: "keys"},
			"values":                   {f: mapValuesV2, Label: "values"},
			"==" + string(types.Nil):   {f: mapCmpNil},
			"!=" + string(types.Nil):   {f: mapNotNil},
			"==" + string(types.Empty): {f: mapCmpEmpty},
			"!=" + string(types.Empty): {f: mapNotEmpty},
			// {}T -- T
			string("&&" + types.Bool):      {f: chunkEqFalseV2, Label: "&&"},
			string("||" + types.Bool):      {f: chunkNeqTrueV2, Label: "||"},
			string("&&" + types.Int):       {f: mapAndIntV2, Label: "&&"},
			string("||" + types.Int):       {f: mapOrIntV2, Label: "||"},
			string("&&" + types.Float):     {f: mapAndFloatV2, Label: "&&"},
			string("||" + types.Float):     {f: mapOrFloatV2, Label: "||"},
			string("&&" + types.String):    {f: mapAndStringV2, Label: "&&"},
			string("||" + types.String):    {f: mapOrStringV2, Label: "||"},
			string("&&" + types.Regex):     {f: mapAndRegexV2, Label: "&&"},
			string("||" + types.Regex):     {f: mapOrRegexV2, Label: "||"},
			string("&&" + types.Time):      {f: mapAndTimeV2, Label: "&&"},
			string("||" + types.Time):      {f: mapOrTimeV2, Label: "||"},
			string("&&" + types.Dict):      {f: mapAndDictV2, Label: "&&"},
			string("||" + types.Dict):      {f: mapOrDictV2, Label: "||"},
			string("&&" + types.ArrayLike): {f: mapAndArrayV2, Label: "&&"},
			string("||" + types.ArrayLike): {f: mapOrArrayV2, Label: "||"},
			string("&&" + types.MapLike):   {f: mapAndMapV2, Label: "&&"},
			string("||" + types.MapLike):   {f: mapOrMapV2, Label: "||"},
		},
		types.ResourceLike: {
			// == / !=
			string("==" + types.Nil): {f: bindingEqNil, Label: "=="},
			string("!=" + types.Nil): {f: bindingNeqNil, Label: "!="},
			// TODO: correctly implement this for list type resources
			string("==" + types.Empty): {f: bindingEqNil, Label: "=="},
			string("!=" + types.Empty): {f: bindingNeqNil, Label: "!="},
			// fields
			"where":     {f: resourceWhereV2},
			"$whereNot": {f: resourceWhereNotV2},
			"sample":    {f: resourceSample},
			"map":       {f: resourceMapV2},
			"length":    {f: resourceLengthV2},
			"{}": {f: func(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
				return e.runBlock(bind, chunk.Function.Args[0], chunk.Function.Args[1:], ref)
			}},
			// TODO: [#32] unique builtin fields that need a long-term support in LR
			string(types.Resource("parse") + ".date"):     {f: resourceDateV2},
			string(types.Resource("parse") + ".duration"): {f: resourceDuration},
		},
	}

	validateBuiltinFunctionsV2()
}

func validateBuiltinFunctionsV2() {
	missing := []string{}

	// dict must have all string methods supported
	dictFun := BuiltinFunctionsV2[types.Dict]
	if dictFun == nil {
		dictFun = map[string]chunkHandlerV2{}
	}

	stringFun := BuiltinFunctionsV2[types.String]
	if stringFun == nil {
		stringFun = map[string]chunkHandlerV2{}
	}

	for id := range stringFun {
		if _, ok := dictFun[id]; !ok {
			missing = append(missing, fmt.Sprintf("dict> missing dict counterpart of string function %#v", id))
		}
	}

	// finalize
	if len(missing) == 0 {
		return
	}
	fmt.Println("Missing functions:")
	for _, msg := range missing {
		fmt.Println(msg)
	}
	panic("missing functions must be added")
}

func runResourceFunction(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	if bind.Value == nil {
		e.cache.Store(ref, &stepCache{
			Result: NilData,
		})
		return NilData, 0, nil
	}

	rr, ok := bind.Value.(Resource)
	if !ok {
		// TODO: can we get rid of this fmt call
		return nil, 0, fmt.Errorf("cannot cast resource to resource type: %+v", bind.Value)
	}

	// A resource reached by resolving into another asset names the runtime that
	// answers it (ADR 031). That redirect is the whole of cross-asset routing:
	// everything below is unchanged, because the schema lookup, the watcher and
	// the field read all just go to a different runtime.
	rt := e.ctx.runtime
	var foreign Runtime
	if bound, ok := bind.Value.(RuntimeBoundResource); ok {
		if boundRuntime := bound.MqlRuntime(); boundRuntime != nil {
			rt, foreign = boundRuntime, boundRuntime
		}
	}

	resource := rt.Schema().Lookup(rr.MqlName())
	if resource == nil {
		return nil, 0, fmt.Errorf("cannot retrieve resource definition for resource %q", rr.MqlName())
	}

	// record this watcher on the executors watcher IDs
	wid := e.watcherUID(ref)
	// log.Debug().Str("wid", wid).Msg("exec> add watcher id ")
	e.watcherIds.Store(wid)
	if foreign != nil {
		// Unregistering walks watcherIds against the executor's own runtime, so
		// a watcher placed on another one has to say where it went or it is
		// never taken down.
		e.foreignWatchers.Store(wid, foreign)
	}

	// watch this field in the resource
	err := rt.WatchAndUpdate(rr, chunk.Id, wid, func(fieldData any, fieldError error) {
		// A field can be missing from the schema when the compiled bundle and
		// the loaded provider disagree (e.g. the provider was updated at runtime
		// independently of the bundle version). Fall back to Unset rather than
		// crash, but log it so the schema mismatch stays observable.
		fieldType := types.Unset
		if field := resource.Fields[chunk.Id]; field != nil {
			fieldType = types.Type(field.Type)
		} else {
			log.Warn().Str("resource", rr.MqlName()).Str("field", chunk.Id).Msg("exec> field missing from schema in WatchAndUpdate callback")
		}
		// The field's value arrives here rather than as a return, so an optional
		// link has to tag its null on this path too.
		//
		// Note this tags a field that *resolved* and simply holds null, not one
		// that failed to resolve - a resource field always resolves, unlike a map
		// key, which can be absent (that case is caught in mapGetIndex /
		// dictGetIndex). Tagging both is the point rather than an oversight: an
		// optional link marks its null whatever the cause, which is what lets a
		// single `?` cover an absent key and a present-but-null value in the same
		// position. See ADR 043 §1. An error is left alone - shortCircuitNull
		// returns res untouched when res.Error is set - so a genuine field
		// failure still propagates as an error.
		// A resource answered by a foreign runtime lives in that asset's tree,
		// so the next chunk in the chain has to keep asking the same runtime.
		data := shortCircuitNull(chunk, &RawData{
			Type:  fieldType,
			Value: bindResourceValues(fieldData, foreign),
			Error: fieldError,
		})
		e.cache.Store(ref, &stepCache{
			Result: data,
		})

		codeID, ok := e.callbackPoints[ref]
		if ok {
			e.callback(&RawResult{Data: data, CodeID: codeID})
		}

		if fieldError != nil {
			e.triggerChainError(ref, fieldError)
		}

		e.triggerChain(ref, data)
	})
	if err != nil {
		// A field this reader has never heard of, in a bundle that already told
		// us it was compiled against a newer provider, is not a broken query -
		// it is a field this build was never going to have. Drop that one field
		// and let the rest of the query run, rather than failing all of it for
		// the sake of a value no version of this binary could produce.
		//
		// The evidence matters. Without a skew policy the same missing field is
		// a typo or a compiler defect, and degrading it would bury a real bug.
		if data, degraded := e.degradeUnavailableField(resource, chunk, err); degraded {
			e.cache.Store(ref, &stepCache{Result: data})
			if codeID, ok := e.callbackPoints[ref]; ok {
				e.callback(&RawResult{Data: data, CodeID: codeID})
			}
			e.triggerChain(ref, data)
			return nil, 0, nil
		}

		if _, ok := err.(resources.NotReadyError); !ok {
			fieldType := types.Unset
			if field := resource.Fields[chunk.Id]; field != nil {
				fieldType = types.Type(field.Type)
			}

			e.cache.Store(ref, &stepCache{
				Result: &RawData{
					Type:  fieldType,
					Value: nil,
					Error: err,
				},
			})
		}
	}

	// we are done executing this chain
	return nil, 0, err
}

// degradeUnavailableField decides whether a failed field read is version skew
// that may be dropped, and builds the value that stands in for it.
//
// The stand-in keeps the field's declared type even though the reader's schema
// has no definition to take it from: the compiler baked the writer's type into
// the chunk, so the bytecode still knows what the field was meant to be. That
// matters because an untyped null is what produces "a primitive with no type
// information, coercing to null" downstream - a value that names neither the
// field it came from nor why it is missing.
func (e *blockExecutor) degradeUnavailableField(resource *resources.ResourceInfo, chunk *Chunk, err error) (*RawData, bool) {
	var notFound *ErrFieldNotFound
	if !errors.As(err, &notFound) {
		return nil, false
	}

	reason := e.ctx.skew.Reason(resource.Provider)
	if reason == "" {
		return nil, false
	}

	typ := types.Type(chunk.Function.GetType())
	if typ == "" {
		typ = types.Unset
	}

	log.Debug().
		Str("resource", notFound.Resource).
		Str("field", notFound.Field).
		Str("reason", reason).
		Msg("exec> dropping a field this provider version does not have")

	return &RawData{
		Type: typ,
		Error: &errFieldUnavailable{
			resource: notFound.Resource,
			field:    notFound.Field,
			reason:   reason,
		},
	}, true
}

// BuiltinFunction provides the handler for this type's function
func BuiltinFunctionV2(typ types.Type, name string) (*chunkHandlerV2, error) {
	// $translate is bound to whatever the original chunk was bound to, which can
	// be any type at all, so it is answered before the per-type tables rather
	// than registered into every one of them.
	if name == TranslateChunkID {
		// Built here rather than held in a package var: the handler reaches
		// runBlock, which reaches back into this function, and Go rejects that
		// as an initialization cycle at package scope.
		return &chunkHandlerV2{f: runTranslate, Label: TranslateChunkID}, nil
	}

	underlying := typ.Underlying()
	h, ok := BuiltinFunctionsV2[underlying]
	if !ok {
		return nil, errors.New("cannot find functions for type '" + typ.Label() + "' (called '" + name + "')")
	}
	fh, ok := h[name]
	if !ok {
		return nil, errors.New("cannot find function '" + name + "' for type '" + typ.Label() + "'")
	}
	return &fh, nil
}

// ErrStrict identifies every error that exists only because strict mode is on
// (ADR 043). Match it with errors.Is to tell "this chain would have resolved in
// non-strict mode" apart from a genuine failure - enough to attach a "did you
// mean `?`" hint, or to report the two classes separately.
//
// It is never returned on its own; the concrete errors carry the detail.
var ErrStrict = errors.New("strict mode")

// errNullBinding reports a link that could not resolve because the value it
// reads from is null. Only produced under strict mode; see ADR 043.
type errNullBinding struct {
	field string
}

func (e *errNullBinding) Error() string {
	return "cannot access \"" + e.field + "\", the value it reads from is null"
}

func (e *errNullBinding) Is(target error) bool { return target == ErrStrict }

// resolveNullBinding applies the strict-mode rule for a link whose binding came
// back null, before the link's handler ever runs.
//
// It returns (result, true) when the caller should stop and use that result, and
// (nil, false) when the link should proceed to its handler as usual.
func (e *blockExecutor) resolveNullBinding(bind *RawData, chunk *Chunk) (*RawData, bool) {
	if bind.Value != nil || bind.Error != nil {
		return nil, false
	}

	f := chunk.Function
	if f == nil || f.Nullability == Function_NULLABILITY_UNSPECIFIED {
		// Non-strict, or an operator: fall through to the handler, which keeps
		// its own long-standing answer for a null receiver. This is also what
		// leaves `== null`, `!= empty` and the boolean operators working, since
		// the compiler never marks them (ADR 043 §2).
		return nil, false
	}

	// The chunk's declared output type, so a short-circuited null still types
	// correctly for whatever consumes it next.
	//
	// The fallback is defensive, not a real case: every function chunk the
	// compiler emits sets Function.Type, and one that does not is a hand-built
	// chunk. It also cannot mistype what a consumer sees, because a
	// short-circuited null is re-stamped with its own output type by each link
	// it passes through - the only type ever observed is that of the last link
	// in the chain, and that link came from the compiler like the rest. Falling
	// back to the binding's type keeps the value typed rather than empty.
	typ := types.Type(f.Type)
	if typ == "" {
		typ = bind.Type
	}

	// A walk towards a dotted key is mid-lookup, not null, so the next key
	// lookup has to run for the path to resolve (see dictWalk). Only a key
	// lookup continues one; anything else reading through this null is reading
	// through a null, and a `?` upstream ends the walk rather than widening its
	// guard. Sits below the non-strict return, so a default compile never
	// reaches it.
	if bind.dictPath != nil && !bind.ShortCircuited &&
		(chunk.Id == "[]" || chunk.Id == "[]?") {
		return nil, false
	}

	// A required link errors - unless the null reaching it was produced by an
	// upstream `?`, which passes through every downstream link untouched. That
	// pass-through is the short circuit: `a?.b.c` yields null when `a` is null
	// without ever running `.b` or `.c`, while `a?.b.c` with `a` set and `b` null
	// still errors at `.c`, the same as optional chaining in JavaScript.
	if f.Nullability == Function_NULLABILITY_REQUIRED && !bind.ShortCircuited {
		return &RawData{Type: typ, Error: &errNullBinding{field: linkName(chunk)}}, true
	}

	return &RawData{Type: typ, ShortCircuited: true}, true
}

// linkName is what a diagnostic should call this link. A key lookup is spelled
// `[]` in the bytecode whether the author wrote `m["k"]` or the bare-word `m.k`,
// so naming the chunk would report `[]` instead of the key the user typed.
func linkName(chunk *Chunk) string {
	if chunk.Id != "[]" && chunk.Id != "[]?" {
		return chunk.Id
	}
	if args := chunk.Function.GetArgs(); len(args) == 1 && types.Type(args[0].Type) == types.String {
		return string(args[0].Value)
	}
	return chunk.Id
}

// shortCircuitNull tags a null that an optional link produced, so that every
// downstream link passes it through instead of erroring on it.
//
// It returns a copy rather than mutating, because handlers hand back shared
// package-level values (NilData, BoolTrue, ...) and tagging one in place would
// corrupt it for every other caller in the process.
func shortCircuitNull(chunk *Chunk, res *RawData) *RawData {
	if res == nil || res.Value != nil || res.Error != nil || res.ShortCircuited {
		return res
	}
	if chunk.Function.GetNullability() != Function_NULLABILITY_OPTIONAL {
		return res
	}
	return &RawData{Type: res.Type, ShortCircuited: true}
}

// this is called for objects that call a function
func (e *blockExecutor) runBoundFunction(bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	log.Trace().Uint64("ref", ref).Str("id", chunk.Id).Msg("exec> run bound function")

	// Strict mode decides what a null binding means before dispatch, so every
	// link answers to one rule instead of the ~100 independent nil branches the
	// handlers carry. Those branches still run in non-strict mode, unchanged.
	if res, handled := e.resolveNullBinding(bind, chunk); handled {
		e.cache.Store(ref, &stepCache{Result: res})
		if res.Error != nil {
			return nil, 0, res.Error
		}
		return res, 0, nil
	}

	// check if the resource defines the function to allow providers to override
	// builtin functions like `length` or any other function
	if bind.Type.IsResource() && bind.Value != nil {
		rr := bind.Value.(Resource)
		resource := e.ctx.runtime.Schema().Lookup(rr.MqlName())
		_, _, override := e.ctx.runtime.Schema().FindField(resource, chunk.Id)
		if override {
			return runResourceFunction(e, bind, chunk, ref)
		}
	}

	fh, err := BuiltinFunctionV2(bind.Type, chunk.Id)
	if err == nil {
		res, dref, err := fh.f(e, bind, chunk, ref)
		if res != nil {
			res = shortCircuitNull(chunk, res)
			e.cache.Store(ref, &stepCache{Result: res})
		}
		if err != nil {
			e.cache.Store(ref, &stepCache{Result: &RawData{
				Error: err,
			}})
		}
		return res, dref, err
	}

	if bind.Type.IsResource() {
		return runResourceFunction(e, bind, chunk, ref)
	}

	return nil, 0, err
}
